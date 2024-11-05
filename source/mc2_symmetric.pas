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
unit mc2_symmetric;

interface

uses System.SysUtils, System.Classes;

resourcestring
  SErrorAESLength = 'Unknown AES length';
  SErrorCipherAlgo = 'Unknown cipher alogrithm';

type
  TC2SymKeyGen = (kgPassword, kgKey);

  TC2SymConfig = class
  strict private
    FCipherAlgo: string;
    FLenKeyBits: integer;
    FHMacAlgo: string;
    FLenIVBits: integer;
  public
    constructor Create(const aCipher: string; const lenKeyBits: integer;
      const aHMac: string);
    property lenKeyBits: integer read FLenKeyBits;
    property lenIVBits: integer read FLenIVBits;
    property aCipher: string read FCipherAlgo;
    property aHMac: string read FHMacAlgo;
  end;

  // After creation, this thing is immutable.
  TC2SymParams = class
  strict private
    FKeyGen: TC2SymKeyGen;

    { Key section }
    FKey: TBytes;
    FIV: TBytes;

    { PBE section }
    // TODO: store pwd encrypted
    FSalt: TBytes;
    FIter: integer;
    FPwd: TBytes;
  public
    constructor Create(const arPwd: TBytes; const lenSaltBits: integer;
      const iter: integer); overload;
    constructor Create(const arKey: TBytes; const lenIVBits: integer); overload;
    property salt: TBytes read FSalt;
    property iter: integer read FIter;
    property pwd: TBytes read FPwd;
    property KeyGen: TC2SymKeyGen read FKeyGen;
    property Key: TBytes read FKey;
    property iv: TBytes read FIV;
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
    class function getHMAC(const cfg: TC2SymConfig;
      const params: TC2SymParams): IC2HMac;
  end;

  IC2Cipher = interface
    function Encrypt(const arPlain: TBytes): TBytes;
    function Decrypt(const arCipher: TBytes): TBytes;
  end;

  TC2Cipher = class
  public
    class function getAlgoNames: TStrings;
    class function getKeyLengths: TStrings;
    class function getCipher(const cfg: TC2SymConfig;
      const params: TC2SymParams): IC2Cipher;
  end;

implementation

uses ClpIBufferedCipher, ClpCipherUtilities, ClpIDigest,
  ClpICipherParameters, ClpPkcs5S2ParametersGenerator, System.Math,
  ClpIMac, ClpIHMac, ClpMacUtilities, ClpParametersWithIV,
  System.Types, System.StrUtils, ClpParameterUtilities,
  ClpIKeyParameter, ClpIParametersWithIV, mc2_main;

type

  TC2SymHMacImp = class(TInterfacedObject, IC2HMac)
  strict private
    FIMac: IMac;
    procedure InitFromPassword(const arPwd, salt: TBytes; const iter: integer);
    procedure InitFromKey(const arKey: TBytes);
  public
    constructor Create(const algo: string; const arPwd, salt: TBytes;
      const iter: integer); overload;
    constructor Create(const cfg: TC2SymConfig;
      const params: TC2SymParams); overload;
    destructor Destroy; override;
    function GenerateMAC(const arPlain: TBytes): TBytes;
    function IsMacValid(const arPlain: TBytes; const arMac: TBytes): boolean;
  end;

  TC2SymCipherImp = class(TInterfacedObject, IC2Cipher)
  strict private
    FCipher: IBufferedCipher;
    FParams: ICipherParameters;
    FAlgorithm: string;
    FMode: string;
    FPadding: string;
    procedure InitFromKey(const arKey: TBytes; const arIV: TBytes);
    procedure InitFromPassword(const cfg: TC2SymConfig;
      const params: TC2SymParams);
  public
    constructor Create(const cfg: TC2SymConfig; const params: TC2SymParams);
    destructor Destroy; override;
    function Encrypt(const arPlain: TBytes): TBytes;
    function Decrypt(const arCipher: TBytes): TBytes;
  end;

  { TC2SymCipherImp }
{$REGION TC2SymCipherImp }

constructor TC2SymCipherImp.Create(const cfg: TC2SymConfig;
  const params: TC2SymParams);
var
  items: TStringDynArray;
  len: integer;
begin
  items := SplitString(cfg.aCipher, '/');
  len := Length(items);
  if (len <> 3) then
    raise Exception.CreateRes(@SErrorCipherAlgo);
  if (items[0] <> 'AES') then
    raise Exception.CreateRes(@SErrorCipherAlgo);
  FAlgorithm := items[0];
  FMode := items[1];
  FPadding := items[2];

  FCipher := TCipherUtilities.getCipher(cfg.aCipher);

  // Init FParams
  case params.KeyGen of
    kgPassword:
      InitFromPassword(cfg, params);
    kgKey:
      InitFromKey(params.Key, params.iv);
  else
    raise Exception.CreateRes(@SErrorCipherAlgo);
  end;
end;

function TC2SymCipherImp.Decrypt(const arCipher: TBytes): TBytes;
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

destructor TC2SymCipherImp.Destroy;
begin
  FCipher := nil;
  FParams := nil;
  inherited;
end;

function TC2SymCipherImp.Encrypt(const arPlain: TBytes): TBytes;
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

procedure TC2SymCipherImp.InitFromKey(const arKey, arIV: TBytes);
var
  kp: IKeyParameter;
  prmKeyIV: IParametersWithIV;
begin
  kp := TParameterUtilities.CreateKeyParameter(FAlgorithm, arKey);
  if FMode = 'ECB' then
    FParams := kp
  else
  begin
    prmKeyIV := TParametersWithIV.Create(kp, arIV);
    FParams := prmKeyIV;
  end;
end;

procedure TC2SymCipherImp.InitFromPassword(const cfg: TC2SymConfig;
  const params: TC2SymParams);
var
  dig: IDigest;
  pgen: TPkcs5S2ParametersGenerator;
begin
  pgen := nil;
  try
    // TODO: make a param?
    dig := TC2Digest.getDigest('SHA-256');
    pgen := TPkcs5S2ParametersGenerator.Create(dig);
    pgen.Init(params.pwd, params.salt, params.iter);
    if FMode = 'ECB' then
      // ECB is the only mode without IV.
      FParams := pgen.GenerateDerivedParameters(FAlgorithm, cfg.lenKeyBits)
    else
      FParams := pgen.GenerateDerivedParameters(FAlgorithm, cfg.lenKeyBits,
        cfg.lenIVBits);
  finally
    if assigned(pgen) then
      pgen.Free;
  end;
end;

{$ENDREGION}
{ TC2SymParams }
{$REGION TC2SymParams }

constructor TC2SymParams.Create(const arPwd: TBytes; const lenSaltBits: integer;
  const iter: integer);
var
  lenS: integer;
const
  MIN_PKCS5_SALT_LEN_BITS = 64;
  MIN_ITERATIONS = 10000;
begin
  FKeyGen := kgPassword;
  FPwd := arPwd;
  FIter := Max(iter, MIN_ITERATIONS);

  lenS := Max(lenSaltBits, MIN_PKCS5_SALT_LEN_BITS);
  FSalt := TC2Random.GenerateKey(lenS);
end;

constructor TC2SymParams.Create(const arKey: TBytes; const lenIVBits: integer);
begin
  FKeyGen := kgKey;
  FKey := arKey;
  FIV := TC2Random.GenerateKey(lenIVBits);
end;
{$ENDREGION}
{ TC2SymHMacImp }
{$REGION TC2SymHMacImp }

constructor TC2SymHMacImp.Create(const cfg: TC2SymConfig;
  const params: TC2SymParams);
var
  dig: IDigest;
  pgen: TPkcs5S2ParametersGenerator;
  cp: ICipherParameters;
  hm: IHMac;
  len: integer;
begin
  FIMac := TMacUtilities.GetMac(cfg.aHMac);
  case params.KeyGen of
    kgPassword:
      InitFromPassword(params.pwd, params.salt, params.iter);
    kgKey:
      InitFromKey(params.Key);
  end;
end;

constructor TC2SymHMacImp.Create(const algo: string; const arPwd, salt: TBytes;
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
    if assigned(pgen) then
      FreeAndNil(pgen);
  end;
end;

destructor TC2SymHMacImp.Destroy;
begin
  FIMac := nil;
  inherited;
end;

function TC2SymHMacImp.GenerateMAC(const arPlain: TBytes): TBytes;
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

procedure TC2SymHMacImp.InitFromKey(const arKey: TBytes);
var
  kp: IKeyParameter;
begin
  kp := nil;
  try
    kp := TParameterUtilities.CreateKeyParameter('AES', arKey);
    FIMac.Init(kp);
  finally
    kp := nil;
  end;
end;

procedure TC2SymHMacImp.InitFromPassword(const arPwd, salt: TBytes;
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
    hm := FIMac as IHMac;
    dig := hm.GetUnderlyingDigest;
    pgen := TPkcs5S2ParametersGenerator.Create(dig);
    pgen.Init(arPwd, salt, iter);
    len := FIMac.GetMacSize * 8;
    cp := pgen.GenerateDerivedMacParameters(len);
    FIMac.Init(cp);
  finally
    if assigned(pgen) then
      FreeAndNil(pgen);
  end;
end;

function TC2SymHMacImp.IsMacValid(const arPlain, arMac: TBytes): boolean;
var
  msgMac: TBytes;
  m1, m2: string;
begin
  msgMac := GenerateMAC(arPlain);
  m1 := TC2Base64.Encode(msgMac);
  m2 := TC2Base64.Encode(arMac);
  Result := m1.Equals(m2);
end;
{$ENDREGION}
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

class function TC2HMac.getHMAC(const cfg: TC2SymConfig;
  const params: TC2SymParams): IC2HMac;
begin
  Result := TC2SymHMacImp.Create(cfg, params);
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

class function TC2Cipher.getKeyLengths: TStrings;
begin
  Result := TStringList.Create;
  Result.Add('128');
  Result.Add('192');
  Result.Add('256');
end;

class function TC2Cipher.getCipher(const cfg: TC2SymConfig;
  const params: TC2SymParams): IC2Cipher;
begin
  Result := TC2SymCipherImp.Create(cfg, params);
end;

{ TC2SymConfig }

constructor TC2SymConfig.Create(const aCipher: string;
  const lenKeyBits: integer; const aHMac: string);
begin
  FLenIVBits := 128; // 16 * 8;
  if (lenKeyBits = 128) or (lenKeyBits = 192) or (lenKeyBits = 256) then
    FLenKeyBits := lenKeyBits
  else
    raise Exception.CreateRes(@SErrorAESLength);

  FCipherAlgo := aCipher;
  FHMacAlgo := aHMac;
  FLenIVBits := 128; // For AES, IV length = 16 * 8;
end;

end.
