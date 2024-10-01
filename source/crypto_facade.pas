unit crypto_facade;

interface

uses System.SysUtils, ClpRandom, SbpBase32, SbpIBase32, SbpBase16;
// , SbpBase32Alphabet;

type

  TCryptoItem = record
    Item: TBytes;
    Enc32: string;
    constructor Create(const pItem: TBytes);
  end;

  TCryptoFacade = class
  strict private
  const
  // PKCS = Public-Key Cryptography Standards
  // https://datatracker.ietf.org/doc/html/rfc2898
    PKCS5_SALT_LEN = Int32(8);
    SALT_MAGIC_LEN = Int32(8);
    // SALT_SIZE = Int32(8);
    SALT_MAGIC: String = 'Salted__';
    AES_256_KEY_LEN_BYTES = 32;
    AES_256_IV_LEN_BYTES = 16;

  var
    mGen: TRandom;

    function GenerateSalt: TBytes;
    function GenerateHash(const digestname: string; const ar: array of TBytes;
      const lenItem: integer): TCryptoItem;
  public
    constructor Create;
    destructor Destroy; override;
    function GenRandomInt: Int32;
    function GenKey32: TCryptoItem;
    procedure EncodeAES256CBC(const password: string; const useSalt: boolean;
      var poSalt, poKey, poIV: string);
  end;

implementation

uses ClpCipherUtilities, ClpIBufferedCipher, ClpIDigest, ClpDigestUtilities;

constructor TCryptoFacade.Create;
begin
  mGen := TRandom.Create;
end;

destructor TCryptoFacade.Destroy;
begin
  if Assigned(mGen) then
  begin
    mGen.Free;
    mGen := nil;
  end;
  inherited;
end;

procedure TCryptoFacade.EncodeAES256CBC(const password: string;
  const useSalt: boolean; var poSalt, poKey, poIV: string);
var
  cp: IBufferedCipher;
  arSalt, arPassword: TBytes;
  salt, key, iv: TCryptoItem;
  ar: array of TBytes;
const
  CRYPTO_NAME = 'AES/CBC/PKCS7PADDING';
begin
  arPassword := TEncoding.UTF8.GetBytes(password);

  if useSalt then
  begin
    arSalt := GenerateSalt;
    salt := TCryptoItem.Create(arSalt);
    poSalt := salt.Enc32;
  end
  else
  begin
    arSalt := nil;
    poSalt := EmptyStr;
  end;

  ar := [arSalt, arPassword];
  key := GenerateHash('SHA-256', ar, AES_256_KEY_LEN_BYTES);
  poKey := key.Enc32;

  ar := [key.Item, arPassword, arSalt];
  iv := GenerateHash('SHA-256', ar, AES_256_IV_LEN_BYTES);
  poIV := iv.Enc32;

  // Test: iv := GenerateHash('MD5', ar, AES_256_IV_LEN_BYTES);

  // System.SetLength(IVBytes, AES_256_IV_LEN_BYTES);
  // cp := TCipherUtilities.GetCipher(CRYPTO_NAME);
  // TParameterUtilities.CreateKeyParameter('AES', KeyBytes)
end;

function TCryptoFacade.GenerateSalt: TBytes;
begin
  System.SetLength(result, PKCS5_SALT_LEN);
  mGen.NextBytes(result);
end;

function TCryptoFacade.GenerateHash(const digestname: string;
  const ar: array of TBytes; const lenItem: integer): TCryptoItem;
var
  res: TBytes;
  dig: IDigest;
  olen: integer;
  // MD5, digest length = 128 bits = 16 bytes. SHA-256 = 256 bits = 32 bytes
begin
  // TODO: exception for invalid digest name
  dig := TDigestUtilities.GetDigest(digestname);
  olen := dig.GetDigestSize;
  if (lenItem < 1) or (lenItem > olen) then
    raise Exception.Create('Digest length out of range.');

  SetLength(res, olen);
  for var a in ar do
    if Assigned(a) then // ignore nil entries
      dig.BlockUpdate(a, 0, Length(a));
  olen := dig.DoFinal(res, 0);
  SetLength(res, lenItem);

  result := TCryptoItem.Create(res);
end;

function TCryptoFacade.GenKey32: TCryptoItem;
var
  ar: TBytes;
begin
  SetLength(ar, 32);
  mGen.NextBytes(ar);
  result := TCryptoItem.Create(ar);
end;

function TCryptoFacade.GenRandomInt: Int32;
begin
  result := mGen.Next;
end;

{ TCryptoItem }

constructor TCryptoItem.Create(const pItem: TBytes);
begin
  if Assigned(pItem) then
  begin
    Item := pItem;
    Enc32 := TBase32.Rfc4648.Encode(Item, true);
  end
  else
  begin
    SetLength(Item, 0);
    Enc32 := EmptyStr;
  end;
end;

end.
