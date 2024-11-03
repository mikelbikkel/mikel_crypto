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
  SErrorCipherAlgo = 'Unknown cipher alogrithm';

type
  // TC2AES = (caAES128, caAES192, caAES256);

  IC2Cipher = interface
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
    class function StringOf(const data: TBytes): string;
    class function BytesOf(const data: string): TBytes;
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
  TC2AESParams = class
  strict private
    FSalt: TBytes;
    FIter: integer;
    FKeyLength: integer;
    FIVLength: integer;
  public
    constructor Create(const keyLengthBits: integer = 256;
      const lenSalt: integer = 8; const iter: integer = 10000);
    property salt: TBytes read FSalt;
    property iter: integer read FIter;
    property lenKeyBits: integer read FKeyLength;
    property lenIVBits: integer read FIVLength;
  end;

  TC2Cipher = class
  public
    class function getAlgoNames: TStrings;
    class function getPBES2(const algo: string; const arPwd: TBytes;
      const params: TC2AESParams): IC2Cipher;
  end;

implementation

uses ClpIBufferedCipher, ClpCipherUtilities, ClpIDigest, ClpDigestUtilities,
  ClpICipherParameters, ClpPkcs5S2ParametersGenerator, System.Math, ClpRandom,
  ClpHMac, ClpIMac, ClpIHMac, ClpMacUtilities, SbpBase64, ClpIParametersWithIV,
  ClpKeyParameter, System.StrUtils, System.Types;

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

  TC2AESImp = class(TInterfacedObject, IC2Cipher)
  strict private
    FCipher: IBufferedCipher;
    FParams: ICipherParameters;
    FAlgorithm: string;
    FMode: string;
    FPadding: string;
  public
    constructor Create(const algo: string; const arPwd: TBytes;
      const params: TC2AESParams);
    destructor Destroy; override;
    function Encrypt(const arPlain: TBytes): TBytes;
    function Decrypt(const arCipher: TBytes): TBytes;
  end;

  { TC2AESImp }
{$REGION TC2AESImp }

constructor TC2AESImp.Create(const algo: string; const arPwd: TBytes;
  const params: TC2AESParams);
var
  items: TStringDynArray;
  len: integer;
  dig: IDigest;
  pgen: TPkcs5S2ParametersGenerator;
begin
  items := SplitString(algo, '/');
  len := Length(items);
  if (len <> 3) then
    raise Exception.CreateRes(@SErrorCipherAlgo);
  FAlgorithm := items[0];
  FMode := items[1];
  FPadding := items[2];
  if (FAlgorithm <> 'AES') then
    raise Exception.CreateRes(@SErrorCipherAlgo);

  FCipher := TCipherUtilities.GetCipher(algo);

  // TODO: leave as is? Parameter?
  dig := TDigestUtilities.GetDigest('SHA-256');
  pgen := TPkcs5S2ParametersGenerator.Create(dig);
  pgen.Init(arPwd, params.salt, params.iter);
  if FMode = 'ECB' then
    FParams := pgen.GenerateDerivedParameters(FAlgorithm, params.lenKeyBits)
  else
    FParams := pgen.GenerateDerivedParameters(FAlgorithm, params.lenKeyBits,
      params.lenIVBits);
  pgen.Free;
end;

function TC2AESImp.Decrypt(const arCipher: TBytes): TBytes;
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
    on e: Exception do
    begin
      var
      s := e.Message;
    end;

  end;
end;

destructor TC2AESImp.Destroy;
begin
  FCipher := nil;
  FParams := nil;
  inherited;
end;

function TC2AESImp.Encrypt(const arPlain: TBytes): TBytes;
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

constructor TC2AESParams.Create(const keyLengthBits: integer;
  const lenSalt: integer; const iter: integer);
var
  rnd: TRandom;
  lenS: integer;
const
  MIN_PKCS5_SALT_LEN = 8;
  MIN_ITERATIONS = 10000;
begin
  // FAES := aes;
  FIter := Max(iter, MIN_ITERATIONS);
  FIVLength := 128; // 16 * 8;
  if (keyLengthBits = 128) or (keyLengthBits = 192) or (keyLengthBits = 256)
  then
    FKeyLength := keyLengthBits
  else
    raise Exception.CreateRes(@SErrorAESLength);

  rnd := TRandom.Create;
  lenS := Max(lenSalt, MIN_PKCS5_SALT_LEN);
  System.SetLength(FSalt, lenS);
  rnd.NextBytes(FSalt);
  rnd.Free;
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

class function TC2UTF8.BytesOf(const data: string): TBytes;
begin
  Result := TEncoding.UTF8.GetBytes(data);
end;

class function TC2UTF8.StringOf(const data: TBytes): string;
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

{ TC2Cipher }

class function TC2Cipher.getAlgoNames: TStrings;
begin
  Result := TStringList.Create;
  Result.Add('AES/ECB/PKCS7PADDING');
  Result.Add('AES/CBC/PKCS7PADDING');
  Result.Add('AES/CFB/NOPADDING');
  Result.Add('AES/OFB/NOPADDING');
  // Result.Add('BLOWFISH/CBC');
end;

class function TC2Cipher.getPBES2(const algo: string; const arPwd: TBytes;
  const params: TC2AESParams): IC2Cipher;
begin
  Result := TC2AESImp.Create(algo, arPwd, params);
end;

end.
