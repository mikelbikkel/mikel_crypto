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

  TCrypto2Environment = class
  public
    function GetAES(const aesType: TCrypto2AES; const arPwd, arSalt: TBytes;
      const iter: integer): ICryptoAES;
  end;

implementation

uses ClpIBufferedCipher, ClpCipherUtilities, ClpIDigest, ClpDigestUtilities,
  ClpICipherParameters, ClpPkcs5S2ParametersGenerator;

type

  TCryptoAESImp = class(TInterfacedObject, ICryptoAES)
  strict private
    FCipher: IBufferedCipher;
    FParams: ICipherParameters;
  public
    constructor Create(const aesType: TCrypto2AES; const arPwd, arSalt: TBytes;
      const iter: integer);
    destructor Destroy; override;
    function Encrypt(const arPlain: TBytes): TBytes;
    function Decrypt(const arCipher: TBytes): TBytes;
  end;

  { TCrypto2Environment }
{$REGION TCrypto2Environment }

function TCrypto2Environment.GetAES(const aesType: TCrypto2AES;
  const arPwd, arSalt: TBytes; const iter: integer): ICryptoAES;
var
  c: TCryptoAESImp;
begin
  c := TCryptoAESImp.Create(aesType, arPwd, arSalt, iter);
  Result := c;
end;
{$ENDREGION}
{ TCryptoAESImp }
{$REGION TCryptoAESImp }

constructor TCryptoAESImp.Create(const aesType: TCrypto2AES;
  const arPwd, arSalt: TBytes; const iter: integer);
var
  dig: IDigest;
  pgen: TPkcs5S2ParametersGenerator;
  params: ICipherParameters;
  keyLength: integer;
begin
  dig := TDigestUtilities.GetDigest('SHA-256');
  pgen := TPkcs5S2ParametersGenerator.Create(dig);
  pgen.Init(arPwd, arSalt, iter);
  case aesType of
    caAES128:
      keyLength := 16;
    caAES192:
      keyLength := 24;
    caAES256:
      keyLength := 32;
  else
    raise Exception.Create(SErrorAESLength);
  end;

  FParams := pgen.GenerateDerivedParameters('AES', keyLength, 16);
  FCipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
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

end.
