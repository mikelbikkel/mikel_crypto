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
unit crypto_facade;

interface

uses System.SysUtils, ClpRandom;

type
  TCryptoEnvironment = class;

  TCryptoHash = (chMD5, chSHA1, chSHA256, chSHA512);

  THashName = record helper for TCryptoHash
    function toString: string;
  end;

  { block cipher key size  block size  IV size
    AES-128     16 bytes   16 bytes    16 bytes
    AES-192     24 bytes   16 bytes    16 bytes
    AES-256     32 bytes   16 bytes    16 bytes
    Triple DES  24 bytes   8 bytes     8 bytes

    Hash algo. hash size
    MD5        16 bytes 128 bit
    SHA1       20 bytes 160 bit
    SHA256     32 bytes 256 bit
    SHA512     64 bytes 512 bits

    For AES-256 you can use SHA256 to hash the key.
  }

  // TODO: AES192 / AES128.
  // TODO: Enum for cipher names? Cipher interface?
  // TODO:
  TCryptoAES256CBC = class
  strict private

  const
    // PKCS = Public-Key Cryptography Standards
    // https://datatracker.ietf.org/doc/html/rfc2898
    SALT_MAGIC: String = 'Salted__';
    SALT_MAGIC_LEN = Int32(8);
    // AES_256_KEY_LEN_BYTES = 32;
    AES_256_IV_LEN_BYTES = 16;
    CRYPTO_NAME = 'AES/CBC/PKCS7PADDING';

  var
    FEnv: TCryptoEnvironment;
    FUseSalt: boolean;
    FSalt, FKey, FIv: TBytes;

  public
    property Key: TBytes read FKey;
    property Salt: TBytes read FSalt;
    property IV: TBytes read FIv;
    constructor Create(const env: TCryptoEnvironment; const arPassword: TBytes;
      const useSalt: boolean);
    destructor Destroy; override;
    function Encrypt(const arPlain: TBytes): TBytes;
  end;

  // Entry-point.
  // DI for created items.
  TCryptoEnvironment = class
  strict private
    FGen: TRandom;

  public
    constructor Create;
    destructor Destroy; override;
    function GenRandomInt: Int32;
    // Generate a key of 32 random bytes.
    function GenKey32: TBytes;
    function GenerateSalt: TBytes;
    function GenerateHash(const ch: TCryptoHash; const ar: array of TBytes)
      : TBytes; overload;
    function GenerateHash(const ch: TCryptoHash; const data: string)
      : TBytes; overload;

    function GetCipherAES256CBC(const password: string; const useSalt: boolean)
      : TCryptoAES256CBC;
    function Base32_Encode(const data: TBytes): string;
    function Base32_Decode(const data: string): TBytes;
    function Base64_Encode(const data: TBytes): string;
    function Base64_Decode(const data: string): TBytes;
  end;

implementation

uses ClpCipherUtilities, ClpIBufferedCipher, ClpIDigest, ClpDigestUtilities,
  ClpParameterUtilities, SbpBase32, ClpIKeyParameter, ClpIParametersWithIV,
  ClpParametersWithIV, SbpBase64;

function TCryptoEnvironment.Base32_Decode(const data: string): TBytes;
begin
  Result := TBase32.Rfc4648.Decode(data);
end;

function TCryptoEnvironment.Base32_Encode(const data: TBytes): string;
begin
  Result := TBase32.Rfc4648.Encode(data, True);
end;

function TCryptoEnvironment.Base64_Decode(const data: string): TBytes;
begin
  Result := TBase64.UrlEncoding.Decode(data);
end;

function TCryptoEnvironment.Base64_Encode(const data: TBytes): string;
begin
  Result := TBase64.UrlEncoding.Encode(data);
end;

constructor TCryptoEnvironment.Create;
begin
  FGen := TRandom.Create;
end;

destructor TCryptoEnvironment.Destroy;
begin
  if Assigned(FGen) then
  begin
    FGen.Free;
    FGen := nil;
  end;
  inherited;
end;

function TCryptoEnvironment.GenerateHash(const ch: TCryptoHash;
  const ar: array of TBytes): TBytes;
var
  res: TBytes;
  dig: IDigest;
  olen: integer;
  dname: string;
begin
  // TODO: exception for invalid digest name
  dname := ch.toString;
  dig := TDigestUtilities.GetDigest(dname);
  olen := dig.GetDigestSize;

  SetLength(res, olen);
  for var a in ar do
    if Assigned(a) then // ignore nil entries
      dig.BlockUpdate(a, 0, Length(a));

  { olen := } dig.DoFinal(res, 0);
  Result := res;
end;

function TCryptoEnvironment.GenerateHash(const ch: TCryptoHash;
  const data: string): TBytes;
var
  arData: TBytes;
  ar: array of TBytes;
begin
  arData := BytesOf(data);
  ar := [arData];
  Result := GenerateHash(ch, ar);
end;

function TCryptoEnvironment.GenKey32: TBytes;
var
  ar: TBytes;
begin
  SetLength(ar, 32);
  FGen.NextBytes(ar);
  Result := ar;
end;

function TCryptoEnvironment.GenRandomInt: Int32;
begin
  Result := FGen.Next;
end;

function TCryptoEnvironment.GenerateSalt: TBytes;
const
  PKCS5_SALT_LEN = 8;
begin
  System.SetLength(Result, PKCS5_SALT_LEN);
  FGen.NextBytes(Result);
end;

function TCryptoEnvironment.GetCipherAES256CBC(const password: string;
  const useSalt: boolean): TCryptoAES256CBC;
var
  arPassword: TBytes;
begin
  arPassword := BytesOf(password);
  Result := TCryptoAES256CBC.Create(self, arPassword, useSalt);
end;

{ TCryptoAES256CBC }
{$REGION TCryptoAES256CBC }

constructor TCryptoAES256CBC.Create(const env: TCryptoEnvironment;
  const arPassword: TBytes; const useSalt: boolean);
var
  ar: array of TBytes;
begin
  FEnv := env;
  FUseSalt := useSalt;

  if FUseSalt then
  begin
    // A salt makes a hash function look non-deterministic.
    // Hash is not secret, must be stored [somewhere].
    FSalt := FEnv.GenerateSalt;
  end
  else
  begin
    FSalt := nil;
  end;

  ar := [FSalt, arPassword];
  FKey := FEnv.GenerateHash(chSHA256, ar);

  ar := [FKey, arPassword, FSalt];
  FIv := FEnv.GenerateHash(chSHA256, ar);
  SetLength(FIv, AES_256_IV_LEN_BYTES);
end;

destructor TCryptoAES256CBC.Destroy;
begin
  inherited;
end;

function TCryptoAES256CBC.Encrypt(const arPlain: TBytes): TBytes;
var
  cipher: IBufferedCipher;
  prmKey: IKeyParameter; // function GetKey(): TCryptoLibByteArray;
  prmKeyIV: IParametersWithIV;
  LBufStart, Count, BufLen: Int32;
  arCipher: TBytes;
begin
  cipher := TCipherUtilities.GetCipher(CRYPTO_NAME);
  // AES + length(FKey) determine the AES-variant that is created.
  prmKey := TParameterUtilities.CreateKeyParameter('AES', FKey);
  prmKeyIV := TParametersWithIV.Create(prmKey, FIv);

  cipher.Init(True, prmKeyIV); // init encryption cipher
  BufLen := Length(arPlain) + cipher.GetBlockSize;
  if FUseSalt then
    BufLen := BufLen + SALT_MAGIC_LEN + Length(FSalt);
  SetLength(arCipher, BufLen);
  LBufStart := 0;

  Count := cipher.ProcessBytes(arPlain, 0, Length(arPlain), arCipher,
    LBufStart);
  Inc(LBufStart, Count);
  Count := cipher.DoFinal(arCipher, LBufStart);
  Inc(LBufStart, Count);
  SetLength(arCipher, LBufStart);
  Result := arCipher;

  {
    System.SetLength(arCypher, System.Length(plaintext) + LBlockSize +
    SALT_MAGIC_LEN + PKCS5_SALT_LEN);

    LBufStart := 0;

    if useSalt then
    begin
    // System.Move(TConverters.ConvertStringToBytes(SALT_MAGIC, TEncoding.UTF8)[0],
    // Buf[LBufStart], SALT_MAGIC_LEN * System.SizeOf(Byte));
    System.Inc(LBufStart, SALT_MAGIC_LEN);
    // System.Move(SaltBytes[0], Buf[LBufStart],
    // PKCS5_SALT_LEN * System.SizeOf(Byte));
    System.Inc(LBufStart, PKCS5_SALT_LEN);
    end;
  }
end;

{$ENDREGION}

{ THashName }
function THashName.toString: string;
begin
  case self of
    chMD5:
      Result := 'MD5';
    chSHA1:
      Result := 'SHA-1';
    chSHA256:
      Result := 'SHA-256';
    chSHA512:
      Result := 'SHA-512';
  else
    Result := 'Error';
  end;
end;

end.
