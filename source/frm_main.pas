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
    memoDecrypt: TMemo;
    actDecrypt: TAction;
    btnDecrypt: TButton;
    procedure FormCreate(Sender: TObject);
    procedure actGenKeyExecute(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure actDecryptExecute(Sender: TObject);
  private
    mCrypto: TCryptoEnvironment;
    FCipher: TCryptoAESCBC;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.actDecryptExecute(Sender: TObject);
var
  arCipher: TBytes;
  arPlain: TBytes;
begin
  if not Assigned(FCipher) then
    Exit;

  arCipher := mCrypto.BaseDecode(cbBase32, memoCypher.Lines.Text);
  arPlain := FCipher.Decrypt(arCipher);
  memoDecrypt.Lines.Text := StringOf(arPlain);
end;

procedure TfrmMain.actGenKeyExecute(Sender: TObject);
var
  pc: PChar;
  ar: TBytes;
  ctext: TBytes;
begin
  edtKey.Text := EmptyStr;
  edtSalt.Text := EmptyStr;
  edtIV.Text := EmptyStr;
  memoCypher.Lines.Clear;
  memoDecrypt.Lines.Clear;

  if not Assigned(FCipher) then
    FCipher := mCrypto.GetCipherAESCBC(edtPassword.Text, chkSalt.Checked);

  edtKey.Text := mCrypto.BaseEncode(cbBase32, FCipher.Key);
  edtSalt.Text := mCrypto.BaseEncode(cbBase32, FCipher.Salt);
  edtIV.Text := mCrypto.BaseEncode(cbBase32, FCipher.iv);

  ctext := FCipher.Encrypt(ar);
  memoCypher.Lines.Add(mCrypto.BaseEncode(cbBase32, ctext));
end;

procedure TfrmMain.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FCipher) then
    FreeAndNil(FCipher);
  if Assigned(mCrypto) then
    FreeAndNil(mCrypto);
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
