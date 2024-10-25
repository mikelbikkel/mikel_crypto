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
unit frm_main;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, System.Actions,
  Vcl.ActnList, crypto_facade;

type
  TfrmMain = class(TForm)
    Label1: TLabel;
    Label2: TLabel;
    pa_a: TLabel;
    ca_a: TLabel;
    Button1: TButton;
    alMain: TActionList;
    actGenKey: TAction;
    edtKey: TEdit;
    edtPassword: TEdit;
    chkSalt: TCheckBox;
    lblPassword: TLabel;
    cmbCryptoAlgo: TComboBox;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    edtIV: TEdit;
    edtSalt: TEdit;
    Label6: TLabel;
    memoPlain: TMemo;
    memoCypher: TMemo;
    Label7: TLabel;
    procedure FormCreate(Sender: TObject);
    procedure actGenKeyExecute(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    mCrypto: TCryptoEnvironment;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.actGenKeyExecute(Sender: TObject);
var
  cipher: TCryptoAES256CBC;
  pc: PChar;
  ar: TBytes;
  ctext: TBytes;
  cntIn, cntOut: integer;
begin
  edtKey.Text := EmptyStr;
  edtSalt.Text := EmptyStr;
  edtIV.Text := EmptyStr;
  memoCypher.Lines.Clear;

  cipher := mCrypto.GetCipherAES256CBC(edtPassword.Text, chkSalt.Checked);
  edtKey.Text := mCrypto.Base32_Encode(cipher.Key);
  edtSalt.Text := mCrypto.Base32_Encode(cipher.Salt);
  edtIV.Text := mCrypto.Base32_Encode(cipher.iv);

  pc := memoPlain.Lines.GetText;
  ar := TEncoding.UTF8.GetBytes(pc);
  cntIn := Length(ar);
  StrDispose(pc);
  ctext := cipher.Encrypt(ar);
  cntOut := Length(ctext);
  memoCypher.Lines.Add(mCrypto.Base32_Encode(ctext));
  cipher.Free;
end;

procedure TfrmMain.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(mCrypto) then
  begin
    mCrypto.Free;
    mCrypto := nil;
  end;
end;

procedure TfrmMain.FormCreate(Sender: TObject);
var
  rnd: Int32;
const
  S_EURO = #$20AC; // U+20AC
  S_N = #$048A;
  S_A_UPPER = #$0414;
  S_A_LOWER = #$0434;
  S_GAL_C = #$EB42;
begin
  ReportMemoryLeaksOnShutdown := true;

  mCrypto := TCryptoEnvironment.Create;
  rnd := mCrypto.GenRandomInt;
  ca_a.Caption := S_A_UPPER + ' - ' + S_A_LOWER + ' - ' + S_EURO + ' - ' +
    S_GAL_C + ' ] ' + IntToStr(rnd);
end;

end.
