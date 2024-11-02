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
  Vcl.ActnList, crypto_facade, crypto2_facade;

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
    chkUse2: TCheckBox;
    edtMacSend: TEdit;
    edtMacReceive: TEdit;
    procedure FormCreate(Sender: TObject);
    procedure actGenKeyExecute(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure actDecryptExecute(Sender: TObject);
  private
    mCrypto: TCryptoEnvironment;
    FCipher: TCryptoAESCBC;
    FParams: TCrypto2AESParams;
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
  arPlain, arMac: TBytes;
  arPwd: TBytes;
  env: TCrypto2Environment;
  cphr: ICryptoAES;
  mc: IC2HMac;
begin
  arCipher := TC2Base64.Decode(memoCypher.Text);
  if chkUse2.Checked then
  begin
    if not Assigned(FParams) then
      Exit;
    arPwd := TC2UTF8.Decode(edtPassword.Text);
    env := TCrypto2Environment.Create;
    cphr := env.GetAES(arPwd, FParams);
    arPlain := cphr.Decrypt(arCipher);

    mc := TC2HMac.getPBMAC1('HMAC-SHA3-224', arPwd, FParams.salt, FParams.iter);
    arMac := mc.GenerateMAC(arPlain);
    edtMacReceive.Text := TC2Base64.Encode(arMac);
    mc := nil;
    env.Free;
    cphr := nil;
  end
  else
  begin
    if not Assigned(FCipher) then
      Exit;
    arPlain := FCipher.Decrypt(arCipher);
  end;
  memoDecrypt.Text := TC2UTF8.Encode(arPlain);
end;

procedure TfrmMain.actGenKeyExecute(Sender: TObject);
var
  ar, arPwd, arMac: TBytes;
  ctext: TBytes;
  env: TCrypto2Environment;
  cphr: ICryptoAES;
  mc: IC2HMac;
begin
  edtKey.Text := EmptyStr;
  edtSalt.Text := EmptyStr;
  edtIV.Text := EmptyStr;
  edtMacSend.Text := EmptyStr;
  edtMacReceive.Text := EmptyStr;
  memoCypher.Lines.Clear;
  memoDecrypt.Lines.Clear;

  ar := TC2UTF8.Decode(memoPlain.Text);
  arPwd := TC2UTF8.Decode(edtPassword.Text);

  if chkUse2.Checked then
  begin
    if not Assigned(FParams) then
      FParams := TCrypto2AESParams.Create(caAES256, 16);
    edtSalt.Text := TC2Base64.Encode(FParams.salt);

    env := TCrypto2Environment.Create;
    cphr := env.GetAES(arPwd, FParams);
    ctext := cphr.Encrypt(ar);
    mc := TC2HMac.getPBMAC1('HMAC-SHA3-224', arPwd, FParams.salt, FParams.iter);
    arMac := mc.GenerateMAC(ar);
    edtMacSend.Text := TC2Base64.Encode(arMac);
    mc := nil;
    env.Free;
    cphr := nil;
  end
  else
  begin
    if not Assigned(FCipher) then
      FCipher := mCrypto.GetCipherAESCBC(edtPassword.Text, chkSalt.Checked);

    edtKey.Text := TC2Base64.Encode(FCipher.Key);
    edtSalt.Text := TC2Base64.Encode(FCipher.salt);
    edtIV.Text := TC2Base64.Encode(FCipher.iv);

    ctext := FCipher.Encrypt(ar);
  end;
  memoCypher.Text := TC2Base64.Encode(ctext);
end;

procedure TfrmMain.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FCipher) then
    FreeAndNil(FCipher);
  if Assigned(mCrypto) then
    FreeAndNil(mCrypto);
  if Assigned(FParams) then
    FreeAndNil(FParams);
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
