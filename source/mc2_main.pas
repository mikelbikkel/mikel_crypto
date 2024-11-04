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
unit mc2_main;

interface

uses System.SysUtils, System.Classes, ClpIDigest;

resourcestring
  SErrorKeyLength = 'Illegal key length';

type
  TC2Base64 = class
  public
    class function Encode(const data: TBytes): string;
    class function Decode(const data: string): TBytes;
  end;

  // Convert from TBytes to string and from string to TBytes.
  // Internally, it uses UTF8 to bypass codepage issues.
  TC2ConvSBS = class
  public
    class function StringOf(const data: TBytes): string;
    class function BytesOf(const data: string): TBytes;
  end;

  // Add rnd (random number generator)
  TC2Random = class
    class function GenerateKey(const lenKeyBits: integer): TBytes;
  end;

  // Add hsh (hash/digest)
  TC2Digest = class
  public
    class function getAlgoNames: TStrings;
    class function getDigest(const name: string): IDigest;
  end;

implementation

uses SbpBase64, ClpRandom, ClpDigestUtilities, System.StrUtils;

class function TC2Base64.Decode(const data: string): TBytes;
begin
  Result := TBase64.UrlEncoding.Decode(data);
end;

class function TC2Base64.Encode(const data: TBytes): string;
begin
  Result := TBase64.UrlEncoding.Encode(data);
end;

{ TC2UTF8 }

class function TC2ConvSBS.BytesOf(const data: string): TBytes;
begin
  Result := TEncoding.UTF8.GetBytes(data);
end;

class function TC2ConvSBS.StringOf(const data: TBytes): string;
begin
  Result := TEncoding.UTF8.GetString(data);
end;

{ TC2Random }

class function TC2Random.GenerateKey(const lenKeyBits: integer): TBytes;
var
  rnd: TRandom;
  lenBytes: integer;
begin
  if (lenKeyBits mod 8) <> 0 then
    raise Exception.CreateRes(@SErrorKeyLength);

  lenBytes := lenKeyBits div 8;
  rnd := TRandom.Create;
  SetLength(Result, lenBytes);
  rnd.NextBytes(Result);
  rnd.Free;
end;

{ TC2Digest }

class function TC2Digest.getAlgoNames: TStrings;
begin
  Result := TStringList.Create;
  Result.Add('MD2');
  Result.Add('MD4');
  Result.Add('MD5');
  Result.Add('SHA-1');
  Result.Add('SHA-224');
  Result.Add('SHA-256');
  Result.Add('SHA-384');
  Result.Add('SHA-512');
  Result.Add('SHA-512/224');
  Result.Add('SHA-512/256');
end;

class function TC2Digest.getDigest(const name: string): IDigest;
begin
  Result := TDigestUtilities.getDigest(name);
end;

end.
