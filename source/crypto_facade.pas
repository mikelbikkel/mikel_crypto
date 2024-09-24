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
    PKCS5_SALT_LEN = Int32(8);
    SALT_MAGIC_LEN = Int32(8);
    SALT_SIZE = Int32(8);
    SALT_MAGIC: String = 'Salted__';
    AES_256_KEY_LEN_BYTES = 32;
    AES_256_IV_LEN_BYTES = 16;

  var
    mGen: TRandom;

    function GenerateSalt: TBytes;
    function GenerateKey(const parPass: TBytes; const parSalt: TBytes = nil)
      : TCryptoItem;
    function GenerateIV(const keyBtes, passBytes, saltBytes: TBytes)
      : TCryptoItem;
    function GenerateHash(const ar: array of TBytes; const lenItem: integer)
      : TCryptoItem;
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
  arSalt := GenerateSalt;
  arPassword := TEncoding.UTF8.GetBytes(password);

  ar := [arSalt, arPassword];
  key := GenerateHash(ar, AES_256_KEY_LEN_BYTES);

  ar := [key.Item, arPassword, arSalt];
  iv := GenerateHash(ar, AES_256_IV_LEN_BYTES);

  salt := TCryptoItem.Create(arSalt);

  poSalt := salt.Enc32;
  poKey := key.Enc32;
  poIV := iv.Enc32;

  // System.SetLength(IVBytes, AES_256_IV_LEN_BYTES);
  // cp := TCipherUtilities.GetCipher(CRYPTO_NAME);
  // TParameterUtilities.CreateKeyParameter('AES', KeyBytes)
end;

function TCryptoFacade.GenerateSalt: TBytes;
begin
  System.SetLength(result, PKCS5_SALT_LEN);
  mGen.NextBytes(result);
end;

function TCryptoFacade.GenerateHash(const ar: array of TBytes;
  const lenItem: integer): TCryptoItem;
var
  res: TBytes;
  dig: IDigest;
  olen: integer;
begin
  SetLength(res, 32);
  if (lenItem < 1) or (lenItem > 32) then
    raise Exception.Create('Error Message');

  dig := TDigestUtilities.GetDigest('SHA-256');
  for var a in ar do
    dig.BlockUpdate(a, 0, Length(a));
  olen := dig.DoFinal(res, 0);
  olen := dig.GetDigestSize;
  SetLength(res, lenItem);
  result := TCryptoItem.Create(res);
end;

function TCryptoFacade.GenerateIV(const keyBtes, passBytes, saltBytes: TBytes)
  : TCryptoItem;
var
  iv: TBytes;
begin
  SetLength(iv, AES_256_IV_LEN_BYTES);
  result := TCryptoItem.Create(nil);
end;

function TCryptoFacade.GenerateKey(const parPass: TBytes;
  const parSalt: TBytes = nil): TCryptoItem;
var
  arKey: TBytes;
  dig: IDigest;
  len: Int32;
begin
  SetLength(arKey, AES_256_KEY_LEN_BYTES);
  dig := TDigestUtilities.GetDigest('SHA-256');
  dig.BlockUpdate(parPass, 0, Length(parPass));
  if Assigned(parSalt) then
  begin
    dig.BlockUpdate(parSalt, 0, Length(parSalt));
  end;
  len := dig.DoFinal(arKey, 0);
  len := dig.GetDigestSize;
  result := TCryptoItem.Create(arKey);
end;

function TCryptoFacade.GenKey32: TCryptoItem;
var
  ar: TBytes;
  e32: IBase32;
begin
  SetLength(ar, 32);
  mGen.NextBytes(ar);
  result := TCryptoItem.Create(ar);
end;

function TCryptoFacade.GenRandomInt: Int32;
begin
  result := mGen.Next;
end;

{ TCryptoKey }

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
