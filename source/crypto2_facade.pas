{ ******************************************************************************

  Copyright (c) 2023 M van Delft.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  ****************************************************************************** }
unit crypto2_facade;

interface

uses System.SysUtils;

resourcestring
  SErrorAESLength = 'Unknown AES length';

type

  TCrypto2AES = (caAES128, caAES192, caAES256);

  ICryptoAES = interface
    function Encrypt(const arPlain: TBytes): TBytes;
    function Decrypt(const arCipher: TBytes): TBytes;
  end;

  // Separate class for aestype, salt, iter. These must be re-used.
  // Do not store password info.
  // This class generates the salt.
  // After creation, this thing is immutable.
  TCrypto2AESParams = class
  strict private
    FAES: TCrypto2AES;
    FSalt: TBytes;
    FIter: integer;
    FKeyLength: integer;
    FIVLength: integer;

    function getLenKeyBits: integer;
    function getLenIVBits: integer;
  public
    constructor Create(const aes: TCrypto2AES; const iter: integer = 10000);
    property aes: TCrypto2AES read FAES;
    property salt: TBytes read FSalt;
    property iter: integer read FIter;
    property lenKeyBits: integer read getLenKeyBits;
    property lenIVBits: integer read getLenIVBits;
  end;

  TCrypto2Environment = class
  public
    // Factory to create an AES/CBC/PKCS7PADDING cipher
    function GetAES(const arPwd: TBytes; const params: TCrypto2AESParams)
      : ICryptoAES;
  end;

implementation

uses ClpIBufferedCipher, ClpCipherUtilities, ClpIDigest, ClpDigestUtilities,
  ClpICipherParameters, ClpPkcs5S2ParametersGenerator, System.Math, ClpRandom;

type

  TCryptoAESImp = class(TInterfacedObject, ICryptoAES)
  strict private
    FCipher: IBufferedCipher;
    FParams: ICipherParameters;
  public
    constructor Create(const arPwd: TBytes; const params: TCrypto2AESParams);
    destructor Destroy; override;
    function Encrypt(const arPlain: TBytes): TBytes;
    function Decrypt(const arCipher: TBytes): TBytes;
  end;

  { TCrypto2Environment }
{$REGION TCrypto2Environment }

function TCrypto2Environment.GetAES(const arPwd: TBytes;
  const params: TCrypto2AESParams): ICryptoAES;
var
  c: TCryptoAESImp;
begin
  // TODO: Add checks.
  c := TCryptoAESImp.Create(arPwd, params);
  Result := c; // Cast to interface type.
end;
{$ENDREGION}
{ TCryptoAESImp }
{$REGION TCryptoAESImp }

constructor TCryptoAESImp.Create(const arPwd: TBytes;
  const params: TCrypto2AESParams);
var
  dig: IDigest;
  pgen: TPkcs5S2ParametersGenerator;
  len: integer;
const
  LENGTH_IV_BYTES = 16;
begin
  // sha256 digest is 32 bytes long. Long enough to support the AES256 key-size
  // (also 32 bytes).
  dig := TDigestUtilities.GetDigest('SHA-256');
  pgen := TPkcs5S2ParametersGenerator.Create(dig);
  pgen.Init(arPwd, params.salt, params.iter);

  FParams := pgen.GenerateDerivedParameters('AES', params.lenKeyBits,
    params.lenIVBits);
  FCipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  len := FCipher.GetBlockSize;
end;

function TCryptoAESImp.Decrypt(const arCipher: TBytes): TBytes;
var
  BufCounter, Count, BufLen: Int32;
  arPlain: TBytes;
begin
  FCipher.Init(false, FParams);
  BufLen := Length(arCipher);
  SetLength(arPlain, BufLen);
  BufCounter := 0;

  Count := FCipher.ProcessBytes(arCipher, 0, BufLen, arPlain, BufCounter);
  Inc(BufCounter, Count); // BufCounter := BufCounter + Count;
  Count := FCipher.DoFinal(arPlain, BufCounter);
  Inc(BufCounter, Count);

  SetLength(arPlain, BufCounter);
  Result := arPlain;
end;

destructor TCryptoAESImp.Destroy;
begin
  FCipher := nil;
  FParams := nil;
  inherited;
end;

function TCryptoAESImp.Encrypt(const arPlain: TBytes): TBytes;
var
  BufCounter, Count, BufLen: Int32;
  arCipher: TBytes;
begin
  FCipher.Init(True, FParams);
  BufLen := Length(arPlain) + FCipher.GetBlockSize;
  SetLength(arCipher, BufLen);
  BufCounter := 0;

  Count := FCipher.ProcessBytes(arPlain, 0, Length(arPlain), arCipher,
    BufCounter);
  Inc(BufCounter, Count);
  Count := FCipher.DoFinal(arCipher, BufCounter);
  Inc(BufCounter, Count);
  SetLength(arCipher, BufCounter);
  Result := arCipher;
end;
{$ENDREGION}
{ TCrypto2AESParams }

constructor TCrypto2AESParams.Create(const aes: TCrypto2AES;
  const iter: integer);
var
  rnd: TRandom;
const
  PKCS5_SALT_LEN = 8;
  MIN_ITERATIONS = 10000;
begin
  FAES := aes;
  FIter := Max(iter, MIN_ITERATIONS);
  FIVLength := 16;
  case FAES of
    caAES128:
      FKeyLength := 16;
    caAES192:
      FKeyLength := 24;
    caAES256:
      FKeyLength := 32;
  else
    raise Exception.Create(SErrorAESLength);
  end;
  rnd := TRandom.Create;
  System.SetLength(FSalt, PKCS5_SALT_LEN);
  rnd.NextBytes(FSalt);
  rnd.Free;
end;

function TCrypto2AESParams.getLenIVBits: integer;
begin
  Result := FIVLength * 8;
end;

function TCrypto2AESParams.getLenKeyBits: integer;
begin
  Result := FKeyLength * 8;
end;

end.
