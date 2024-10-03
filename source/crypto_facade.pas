unit crypto_facade;

interface

uses System.SysUtils, ClpRandom;

type

  TCryptoItem = record
    Item: TBytes;
    Enc32: string;
    constructor Create(const pItem: TBytes);
  end;

  TCryptoAES256CBC = class
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
    CRYPTO_NAME = 'AES/CBC/PKCS7PADDING';

  var
    FPassword: string;
    FUseSalt: boolean;
    FGen: TRandom;
    FSalt, FKey, FIv: TCryptoItem;

    function GenerateSalt: TBytes;
    function GenerateHash(const digestname: string; const ar: array of TBytes;
      const lenItem: integer): TCryptoItem;
  public
    property Key: TCryptoItem read FKey;
    property Salt: TCryptoItem read FSalt;
    property IV: TCryptoItem read FIv;
    constructor Create(const password: string; const useSalt: boolean);
    destructor Destroy; override;
    function Encode(const arPlain: TBytes): TCryptoItem;
  end;

  TCryptoFacade = class
  strict private
    mGen: TRandom;

  public
    constructor Create;
    destructor Destroy; override;
    function GenRandomInt: Int32;
    function GenKey32: TCryptoItem;
  end;

implementation

uses ClpCipherUtilities, ClpIBufferedCipher, ClpIDigest, ClpDigestUtilities,
  ClpParameterUtilities, SbpBase32, ClpIKeyParameter, ClpIParametersWithIV,
  ClpParametersWithIV;

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
    Enc32 := TBase32.Rfc4648.Encode(Item, True);
  end
  else
  begin
    SetLength(Item, 0);
    Enc32 := EmptyStr;
  end;
end;

{ TCryptoAES256CBC }
{$REGION TCryptoAES256CBC }

constructor TCryptoAES256CBC.Create(const password: string;
  const useSalt: boolean);
var
  arSalt, arPassword, Buf: TBytes;
  ar: array of TBytes;
begin
  FGen := TRandom.Create;
  FPassword := password;
  FUseSalt := useSalt;

  arPassword := TEncoding.UTF8.GetBytes(FPassword);

  if FUseSalt then
  begin
    arSalt := GenerateSalt;
    FSalt := TCryptoItem.Create(arSalt);
  end
  else
  begin
    arSalt := nil;
  end;

  ar := [arSalt, arPassword];
  FKey := GenerateHash('SHA-256', ar, AES_256_KEY_LEN_BYTES);

  ar := [FKey.Item, arPassword, arSalt];
  FIv := GenerateHash('SHA-256', ar, AES_256_IV_LEN_BYTES);
end;

destructor TCryptoAES256CBC.Destroy;
begin
  if Assigned(FGen) then
    FGen.Free;
  inherited;
end;

function TCryptoAES256CBC.Encode(const arPlain: TBytes): TCryptoItem;
var
  cipher: IBufferedCipher;
  prmKey: IKeyParameter; // function GetKey(): TCryptoLibByteArray;
  prmKeyIV: IParametersWithIV;
  LBufStart, Count, BufLen: Int32;
  arCipher: TBytes;
begin
  cipher := TCipherUtilities.GetCipher(CRYPTO_NAME);
  prmKey := TParameterUtilities.CreateKeyParameter('AES', Key.Item);
  prmKeyIV := TParametersWithIV.Create(prmKey, IV.Item);

  cipher.Init(True, prmKeyIV); // init encryption cipher
  BufLen := Length(arPlain) + cipher.GetBlockSize;
  if FUseSalt then
    BufLen := BufLen + SALT_MAGIC_LEN + PKCS5_SALT_LEN;
  SetLength(arCipher, BufLen);
  LBufStart := 0;

  Count := cipher.ProcessBytes(arPlain, 0, Length(arPlain), arCipher,
    LBufStart);
  Inc(LBufStart, Count);
  Count := cipher.DoFinal(arCipher, LBufStart);
  Inc(LBufStart, Count);
  SetLength(arCipher, LBufStart);
  result := TCryptoItem.Create(arCipher);

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

function TCryptoAES256CBC.GenerateHash(const digestname: string;
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

function TCryptoAES256CBC.GenerateSalt: TBytes;
begin
  System.SetLength(result, PKCS5_SALT_LEN);
  FGen.NextBytes(result);
end;
{$ENDREGION}

end.
