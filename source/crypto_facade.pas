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

uses System.SysUtils, ClpRandom, ClpIBufferedCipher;

type
  TCryptoEnvironment = class;

  TCryptoHash = (chMD5, chSHA1, chSHA256, chSHA512);
  TCryptoEncoding = (cbBase64, cbBase32);
  TCryptoAES = (caAES128, caAES192, caAES256);

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
    For the others? Truncate the key to the desired length?

    https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/
    AES modes.
    For block: CBC or ECB. Padding: PKCS5 or PKCS7
    Electronic Code Book - weak. Not recommended.
    Cipher Block Chaining
    using an initialization vector – IV. The IV has the same size as the block that is encrypted. In general, the IV usually is a random number, not a nonce.
    output of block X is XORed with input of block X+1.
    For first block, XOR with IV.
    For stream: CFB (needs IV), OFB (needs IV), CTR (needs an initial counter value as an IV)
    Stream modes do not need padding.
  }

  // TODO: AES192 / AES128.
  // TODO: Enum for cipher names? Cipher interface?
  // TODO:
  TCryptoAESCBC = class
  strict private

  const
    // PKCS = Public-Key Cryptography Standards
    // https://datatracker.ietf.org/doc/html/rfc2898
    // SALT_MAGIC: String = 'Salted__';
    // SALT_MAGIC_LEN = Int32(8);
    CRYPTO_NAME = 'AES/CBC/PKCS7PADDING';

  var
    FAESLength: TCryptoAES;
    FEnv: TCryptoEnvironment;
    FUseSalt: boolean;
    FSalt, FKey, FIv: TBytes;
    function InternalCreateCipher(forEncrypt: boolean): IBufferedCipher;
  public
    property Key: TBytes read FKey;
    property Salt: TBytes read FSalt;
    property IV: TBytes read FIv;
    constructor Create(const env: TCryptoEnvironment; const arPassword: TBytes;
      const useSalt: boolean; const aesType: TCryptoAES = caAES256);
    destructor Destroy; override;
    // TODO: user string for plaintext? Call ENV to xlt between string and tbytes.
    function Encrypt(const arPlain: TBytes): TBytes;
    function Decrypt(const arCipher: TBytes): TBytes;
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

    function GetCipherAESCBC(const password: string; const useSalt: boolean;
      const aesType: TCryptoAES = caAES256): TCryptoAESCBC;
    // Nil returns an empty string.
    function BaseEncode(const enc: TCryptoEncoding; const data: TBytes): string;
    // EmtyStr returns a zero-length byte array
    function BaseDecode(const enc: TCryptoEncoding; const data: string): TBytes;
  end;

implementation

uses ClpCipherUtilities, ClpIDigest, ClpDigestUtilities,
  ClpParameterUtilities, SbpBase32, ClpIKeyParameter, ClpIParametersWithIV,
  ClpParametersWithIV, SbpBase64;

{ TCryptoEnvironment }
{$REGION TCryptoEnvironment }

function TCryptoEnvironment.BaseDecode(const enc: TCryptoEncoding;
  const data: string): TBytes;
begin
  case enc of
    cbBase64:
      Result := TBase64.UrlEncoding.Decode(data);
    cbBase32:
      Result := TBase32.Rfc4648.Decode(data);
  else
    raise Exception.Create('Unknown TCryptoEncoding');
  end;
end;

function TCryptoEnvironment.BaseEncode(const enc: TCryptoEncoding;
  const data: TBytes): string;
begin
  case enc of
    cbBase64:
      Result := TBase64.UrlEncoding.Encode(data);
    cbBase32:
      Result := TBase32.Rfc4648.Encode(data, True);
  else
    raise Exception.Create('Unknown TCryptoEncoding');
  end;
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

function TCryptoEnvironment.GetCipherAESCBC(const password: string;
  const useSalt: boolean; const aesType: TCryptoAES): TCryptoAESCBC;
var
  arPassword: TBytes;
begin
  arPassword := BytesOf(password);
  Result := TCryptoAESCBC.Create(self, arPassword, useSalt);
end;

{$ENDREGION}
{ TCryptoAES256CBC }
{$REGION TCryptoAES256CBC }

constructor TCryptoAESCBC.Create(const env: TCryptoEnvironment;
  const arPassword: TBytes; const useSalt: boolean; const aesType: TCryptoAES);
var
  ar: array of TBytes;
  keyLength: integer;
const
  AES_IV_LEN_BYTES = 16; // for 256, 192 and 128
begin
  FAESLength := aesType;
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
  case FAESLength of
    caAES128:
      keyLength := 16;
    caAES192:
      keyLength := 24;
    caAES256:
      keyLength := 32;
  else
    raise Exception.Create('Unknown AES length');
  end;
  SetLength(FKey, keyLength);

  ar := [FKey, arPassword, FSalt];
  FIv := FEnv.GenerateHash(chSHA256, ar);
  SetLength(FIv, AES_IV_LEN_BYTES);
end;

function TCryptoAESCBC.Decrypt(const arCipher: TBytes): TBytes;
var
  cipher: IBufferedCipher;
  BufCounter, Count, BufLen: Int32;
  arPlain: TBytes;
begin
  cipher := InternalCreateCipher(false);

  BufLen := Length(arCipher);
  SetLength(arPlain, BufLen);
  BufCounter := 0;

  Count := cipher.ProcessBytes(arCipher, 0, BufLen, arPlain, BufCounter);
  Inc(BufCounter, Count); // BufCounter := BufCounter + Count;
  Count := cipher.DoFinal(arPlain, BufCounter);
  Inc(BufCounter, Count);

  SetLength(arPlain, BufCounter);
  Result := arPlain;
end;

destructor TCryptoAESCBC.Destroy;
begin
  inherited;
end;

function TCryptoAESCBC.Encrypt(const arPlain: TBytes): TBytes;
var
  cipher: IBufferedCipher;
  BufCounter, Count, BufLen: Int32;
  arCipher: TBytes;
begin
  cipher := InternalCreateCipher(True);
  BufLen := Length(arPlain) + cipher.GetBlockSize;
  // if FUseSalt then
  // BufLen := BufLen + SALT_MAGIC_LEN + Length(FSalt);
  SetLength(arCipher, BufLen);
  BufCounter := 0;

  Count := cipher.ProcessBytes(arPlain, 0, Length(arPlain), arCipher,
    BufCounter);
  Inc(BufCounter, Count);
  Count := cipher.DoFinal(arCipher, BufCounter);
  Inc(BufCounter, Count);
  SetLength(arCipher, BufCounter);
  Result := arCipher;

  {
    System.SetLength(arCypher, System.Length(plaintext) + LBlockSize +
    SALT_MAGIC_LEN + PKCS5_SALT_LEN);

    BufCounter := 0;

    if useSalt then
    begin
    // System.Move(TConverters.ConvertStringToBytes(SALT_MAGIC, TEncoding.UTF8)[0],
    // Buf[BufCounter], SALT_MAGIC_LEN * System.SizeOf(Byte));
    System.Inc(BufCounter, SALT_MAGIC_LEN);
    // System.Move(SaltBytes[0], Buf[BufCounter],
    // PKCS5_SALT_LEN * System.SizeOf(Byte));
    System.Inc(BufCounter, PKCS5_SALT_LEN);
    end;
  }
end;

function TCryptoAESCBC.InternalCreateCipher(forEncrypt: boolean)
  : IBufferedCipher;
var
  cipher: IBufferedCipher;
  prmKey: IKeyParameter; // function GetKey(): TCryptoLibByteArray;
  prmKeyIV: IParametersWithIV;
begin
  // Decrypt items: Salt. Either user input or remembered (FPassword).
  // IV: can be derived. Or remembered (FIv)
  // Salt: Remember if Salt was used and if so, what the value was (FSalt)

  cipher := TCipherUtilities.GetCipher(CRYPTO_NAME);
  // AES + length(FKey) determine the AES-variant that is created.
  prmKey := TParameterUtilities.CreateKeyParameter('AES', FKey);
  prmKeyIV := TParametersWithIV.Create(prmKey, FIv);

  cipher.Init(forEncrypt, prmKeyIV); // init encryption cipher
  Result := cipher;
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
