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

uses System.SysUtils, System.Classes;

resourcestring
  SErrorAESLength = 'Unknown AES length';

type
  TCrypto2AES = (caAES128, caAES192, caAES256);

  ICryptoAES = interface
    function Encrypt(const arPlain: TBytes): TBytes;
    function Decrypt(const arCipher: TBytes): TBytes;
  end;

  TC2Base64 = class
  public
    class function Encode(const data: TBytes): string;
    class function Decode(const data: string): TBytes;
  end;

  TC2UTF8 = class
  public
    class function Encode(const data: TBytes): string;
    class function Decode(const data: string): TBytes;
  end;

  // Hash-based message authetication code.
  IC2HMac = interface
    function GenerateMAC(const arPlain: TBytes): TBytes;
    function IsMacValid(const arPlain: TBytes; const arMac: TBytes): boolean;
  end;

  // Hash-based message authetication code.
  // Make a deterministic hash-function pseudo-random.
  // Create variation by providing a key or a password.
  // The password also requires a salt and an iteration parameter.
  TC2HMac = class
  public
    class function getAlgoNames: TStrings;
    class function getPBMAC1(const algo: string; const arPwd: TBytes;
      const arSalt: TBytes; const iter: integer): IC2HMac;
    class function getKeyMAC(const algo: string; const arKey: TBytes): IC2HMac;
  end;

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
    constructor Create(const aes: TCrypto2AES; const lenSalt: integer = 8;
      const iter: integer = 10000);
    property aes: TCrypto2AES read FAES;
    property salt: TBytes read FSalt;
    property iter: integer read FIter;
    property lenKeyBits: integer read getLenKeyBits;
    property lenIVBits: integer read getLenIVBits;
  end;

  // Separate class for aestype, salt, iter. These must be re-used.
  // Do not store password info.
  // This class generates the salt.
  TCrypto2Environment = class
  public
    // Factory to create an AES/CBC/PKCS7PADDING cipher
    function GetAES(const arPwd: TBytes; const params: TCrypto2AESParams)
      : ICryptoAES;
  end;

implementation

uses ClpIBufferedCipher, ClpCipherUtilities, ClpIDigest, ClpDigestUtilities,
  ClpICipherParameters, ClpPkcs5S2ParametersGenerator, System.Math, ClpRandom,
  ClpHMac, ClpIMac, ClpIHMac, ClpMacUtilities, SbpBase64, ClpIParametersWithIV,
  ClpKeyParameter;

type

  TPBMAC1Imp = class(TInterfacedObject, IC2HMac)
  strict private
    FIMac: IMac;
  public
    constructor Create(const algo: string; const arPwd, salt: TBytes;
      const iter: integer);
    destructor Destroy; override;
    function GenerateMAC(const arPlain: TBytes): TBytes;
    function IsMacValid(const arPlain: TBytes; const arMac: TBytes): boolean;
  end;

  TKeyMACImp = class(TInterfacedObject, IC2HMac)
  strict private
    FIMac: IMac;
  public
    constructor Create(const algo: string; const arKey: TBytes);
    destructor Destroy; override;
    function GenerateMAC(const arPlain: TBytes): TBytes;
    function IsMacValid(const arPlain: TBytes; const arMac: TBytes): boolean;
  end;

  TCryptoAESImp = class(TInterfacedObject, ICryptoAES)
  strict private
    FCipher: IBufferedCipher;
    FParams: ICipherParameters;
    FIV: TBytes;
  public
    constructor Create(const arPwd: TBytes; const params: TCrypto2AESParams);
    destructor Destroy; override;
    function Encrypt(const arPlain: TBytes): TBytes;
    function Decrypt(const arCipher: TBytes): TBytes;
    property IV: TBytes read FIV;
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
  piv: IParametersWithIV;
begin
  dig := nil;
  pgen := nil;
  try
    dig := TDigestUtilities.GetDigest('SHA-256');
    pgen := TPkcs5S2ParametersGenerator.Create(dig);
    pgen.Init(arPwd, params.salt, params.iter);

    // Creates a key with length = lenKeyBits + lenIVBits.
    // This key is split into an IV part and a key part.
    FParams := pgen.GenerateDerivedParameters('AES', params.lenKeyBits,
      params.lenIVBits);
    piv := FParams as IParametersWithIV;
    FIV := piv.GetIV;
    FCipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  finally
    if Assigned(pgen) then
      FreeAndNil(pgen);
  end;
end;

function TCryptoAESImp.Decrypt(const arCipher: TBytes): TBytes;
var
  BufCounter, Count, BufLen: Int32;
  arPlain: TBytes;
begin
  try
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
  except
    // uses SbpSimpleBaseLibTypes
    // ESimpleBaseLibException = class(Exception);
    //
    // uses HlpHashLibTypes
    // EHashLibException = class(Exception);
    //
    // uses ClpCryptoLibTypes
    // ECryptoLibException = class(Exception);
    // EInvalidCastCryptoLibException = class(EInvalidCast);
    // other cryptolib exceptions are derived from ECryptoLibException

    on e: Exception do
    begin
      var
      s := e.Message;
    end;

  end;
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
  const lenSalt: integer; const iter: integer);
var
  rnd: TRandom;
  lenS: integer;
const
  MIN_PKCS5_SALT_LEN = 8;
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
    raise Exception.CreateRes(@SErrorAESLength);
  end;
  rnd := TRandom.Create;
  lenS := Max(lenSalt, MIN_PKCS5_SALT_LEN);
  System.SetLength(FSalt, lenS);
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

{ TPBMAC1Imp }

constructor TPBMAC1Imp.Create(const algo: string; const arPwd, salt: TBytes;
  const iter: integer);
var
  dig: IDigest;
  pgen: TPkcs5S2ParametersGenerator;
  cp: ICipherParameters;
  hm: IHMac;
  len: integer;
begin
  dig := nil;
  pgen := nil;
  try
    FIMac := TMacUtilities.GetMac(algo);
    hm := FIMac as IHMac;
    dig := hm.GetUnderlyingDigest;
    pgen := TPkcs5S2ParametersGenerator.Create(dig);
    pgen.Init(arPwd, salt, iter);
    len := FIMac.GetMacSize * 8;
    cp := pgen.GenerateDerivedMacParameters(len);
    FIMac.Init(cp);
  finally
    if Assigned(pgen) then
      FreeAndNil(pgen);
  end;
end;

destructor TPBMAC1Imp.Destroy;
begin
  FIMac := nil;
  inherited;
end;

function TPBMAC1Imp.GenerateMAC(const arPlain: TBytes): TBytes;
var
  res: TBytes;
  olen: integer;
begin
  olen := FIMac.GetMacSize;
  SetLength(res, olen);
  FIMac.BlockUpdate(arPlain, 0, Length(arPlain));
  FIMac.DoFinal(res, 0);
  Result := res;
end;

function TPBMAC1Imp.IsMacValid(const arPlain, arMac: TBytes): boolean;
var
  msgMac: TBytes;
  m1, m2: string;
begin
  msgMac := GenerateMAC(arPlain);
  m1 := TC2Base64.Encode(msgMac);
  m2 := TC2Base64.Encode(arMac);
  Result := m1.Equals(m2);
end;

{ TC2Base64 }

class function TC2Base64.Decode(const data: string): TBytes;
begin
  Result := TBase64.UrlEncoding.Decode(data);
end;

class function TC2Base64.Encode(const data: TBytes): string;
begin
  Result := TBase64.UrlEncoding.Encode(data);
end;

{ TC2UTF8 }

class function TC2UTF8.Decode(const data: string): TBytes;
begin
  Result := TEncoding.UTF8.GetBytes(data);
end;

class function TC2UTF8.Encode(const data: TBytes): string;
begin
  Result := TEncoding.UTF8.GetString(data);
end;

{ TC2HMac }

class function TC2HMac.getAlgoNames: TStrings;
begin
  Result := TStringList.Create;
  // SHA1 algorithms
  Result.Add('HMAC-SHA1');
  // SHA2 algorithms
  Result.Add('HMAC-SHA224');
  Result.Add('HMAC-SHA256');
  Result.Add('HMAC-SHA384');
  Result.Add('HMAC-SHA512');
  // SHA3 algorithms
  Result.Add('HMAC-SHA3-224');
  Result.Add('HMAC-SHA3-256');
  Result.Add('HMAC-SHA3-384');
  Result.Add('HMAC-SHA3-512');
end;

class function TC2HMac.getKeyMAC(const algo: string;
  const arKey: TBytes): IC2HMac;
begin
  Result := TKeyMACImp.Create(algo, arKey);
end;

class function TC2HMac.getPBMAC1(const algo: string;
  const arPwd, arSalt: TBytes; const iter: integer): IC2HMac;
begin
  Result := TPBMAC1Imp.Create(algo, arPwd, arSalt, iter);
end;

{ TKeyMACImp }

constructor TKeyMACImp.Create(const algo: string; const arKey: TBytes);
var
  kp: TKeyParameter;
begin
  kp := nil;
  try
    FIMac := TMacUtilities.GetMac(algo);
    kp := TKeyParameter(arKey);
    FIMac.Init(kp);
  finally
    kp := nil;
  end;
end;

destructor TKeyMACImp.Destroy;
begin
  FIMac := nil;
  inherited;
end;

function TKeyMACImp.GenerateMAC(const arPlain: TBytes): TBytes;
var
  res: TBytes;
  olen: integer;
begin
  olen := FIMac.GetMacSize;
  SetLength(res, olen);
  FIMac.BlockUpdate(arPlain, 0, Length(arPlain));
  FIMac.DoFinal(res, 0);
  Result := res;
end;

function TKeyMACImp.IsMacValid(const arPlain, arMac: TBytes): boolean;
var
  msgMac: TBytes;
  m1, m2: string;
begin
  msgMac := GenerateMAC(arPlain);
  m1 := TC2Base64.Encode(msgMac);
  m2 := TC2Base64.Encode(arMac);
  Result := m1.Equals(m2);
end;

end.
