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
  Vcl.ActnList, crypto_facade, mc2_symmetric, Vcl.ExtCtrls;

type
  TfrmMain = class(TForm)
    Label1: TLabel;
    Label2: TLabel;
    pa_a: TLabel;
    ca_a: TLabel;
    Button1: TButton;
    alMain: TActionList;
    actEncrypt: TAction;
    edtKey: TEdit;
    edtPassword: TEdit;
    lblPassword: TLabel;
    cmbCryptoAlgo: TComboBox;
    Label3: TLabel;
    Label4: TLabel;
    memoPlain: TMemo;
    memoCypher: TMemo;
    Label7: TLabel;
    memoDecrypt: TMemo;
    actDecrypt: TAction;
    btnDecrypt: TButton;
    edtMacSend: TEdit;
    edtMacReceive: TEdit;
    cmbKeyLength: TComboBox;
    Label8: TLabel;
    edtSaltLength: TEdit;
    Label9: TLabel;
    edtIterations: TEdit;
    Label10: TLabel;
    Label11: TLabel;
    cmbHMAC: TComboBox;
    Label5: TLabel;
    Label6: TLabel;
    rgKeySource: TRadioGroup;
    actGenerateKey: TAction;
    btnGenerateKey: TButton;
    edtLenPlain: TEdit;
    edtLenCipher: TEdit;
    edtLenMac: TEdit;
    procedure FormCreate(Sender: TObject);
    procedure actEncryptExecute(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure actDecryptExecute(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure actGenerateKeyExecute(Sender: TObject);

  private
    FParams: TC2SymParams;
    FConfig: TC2SymConfig;
    procedure InitParams;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

uses mc2_main;

{$R *.dfm}

procedure TfrmMain.actDecryptExecute(Sender: TObject);
var
  arCipher: TBytes;
  arPlain, arMac: TBytes;
  arPwd: TBytes;
  cphr: IC2Cipher;
  mc: IC2HMac;
  tst: boolean;
begin
  if not Assigned(FParams) then
    Exit;

  arCipher := TC2Base64.Decode(memoCypher.Text);
  arPwd := TC2ConvSBS.BytesOf(edtPassword.Text);

  cphr := TC2Cipher.getCipher(FConfig, FParams);
  arPlain := cphr.Decrypt(arCipher);
  mc := TC2HMac.getHMAC(FConfig, FParams);
  arMac := mc.GenerateMAC(arPlain);
  tst := mc.IsMacValid(arPlain, TC2Base64.Decode(edtMacSend.Text));
  mc := nil;
  cphr := nil;

  edtMacReceive.Text := TC2Base64.Encode(arMac);
  memoDecrypt.Text := TC2ConvSBS.StringOf(arPlain);
end;

procedure TfrmMain.actEncryptExecute(Sender: TObject);
var
  ar, arPwd, arMac: TBytes;
  ctext: TBytes;
  cphr: IC2Cipher;
  mc: IC2HMac;
begin
  edtMacSend.Clear;
  edtMacReceive.Clear;
  memoCypher.Lines.Clear;
  memoDecrypt.Lines.Clear;
  edtLenPlain.Clear;
  edtLenMac.Clear;
  edtLenCipher.Clear;

  InitParams;

  ar := TC2ConvSBS.BytesOf(memoPlain.Text);
  arPwd := TC2ConvSBS.BytesOf(edtPassword.Text);
  edtLenPlain.Text := IntToStr(Length(arPwd)) + ' bytes';

  cphr := TC2Cipher.getCipher(FConfig, FParams);
  ctext := cphr.Encrypt(ar);
  edtLenCipher.Text := IntToStr(Length(ctext)) + ' bytes';
  mc := TC2HMac.getHMAC(FConfig, FParams);
  arMac := mc.GenerateMAC(ar);
  edtLenMac.Text := IntToStr(Length(arMac)) + ' bytes';
  edtMacSend.Text := TC2Base64.Encode(arMac);
  mc := nil;
  cphr := nil;
  memoCypher.Text := TC2Base64.Encode(ctext);
end;

procedure TfrmMain.actGenerateKeyExecute(Sender: TObject);
var
  s: string;
  lenKey: integer;
  key: TBytes;
begin
  edtKey.Clear;
  s := cmbKeyLength.Items[cmbKeyLength.ItemIndex];
  lenKey := StrToInt(s);
  key := TC2Random.GenerateKey(lenKey);
  edtKey.Text := TC2Base64.Encode(key);
end;

procedure TfrmMain.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FParams) then
    FreeAndNil(FParams);
  if Assigned(FConfig) then
    FreeAndNil(FConfig);
end;

procedure TfrmMain.FormCreate(Sender: TObject);
const
  S_EURO = #$20AC; // U+20AC
  S_N = #$048A;
  S_A_UPPER = #$0414;
  S_A_LOWER = #$0434;
  S_GAL_C = #$EB42;
begin
  ReportMemoryLeaksOnShutdown := true;

  ca_a.Caption := S_A_UPPER + ' - ' + S_A_LOWER + ' - ' + S_EURO + ' - ' +
    S_GAL_C + ' ] ';
end;

procedure TfrmMain.FormShow(Sender: TObject);
var
  s: TStrings;
begin
  cmbCryptoAlgo.Items.Clear;
  s := TC2Cipher.getAlgoNames;
  cmbCryptoAlgo.Items := s;
  s.Free;
  cmbCryptoAlgo.ItemIndex := 0;

  cmbKeyLength.Items.Clear;
  s := TC2Cipher.getKeyLengths;
  cmbKeyLength.Items := s;
  s.Free;
  cmbKeyLength.ItemIndex := 0;

  cmbHMAC.Items.Clear;
  s := TC2HMac.getAlgoNames;
  cmbHMAC.Items := s;
  s.Free;
  cmbHMAC.ItemIndex := 1;
end;

procedure TfrmMain.InitParams;
var
  s: string;
  lenSalt, lenKey, iter: integer;
  sC, sH: string;
  arPwd, arKey: TBytes;
begin
  if Assigned(FParams) then
    FreeAndNil(FParams);
  if Assigned(FConfig) then
    FreeAndNil(FConfig);

  sC := cmbCryptoAlgo.Items[cmbCryptoAlgo.ItemIndex];
  sH := cmbHMAC.Items[cmbHMAC.ItemIndex];
  s := cmbKeyLength.Items[cmbKeyLength.ItemIndex];
  lenKey := StrToInt(s);
  FConfig := TC2SymConfig.Create(sC, lenKey, sH);

  case rgKeySource.ItemIndex of
    0: // Password
      begin
        arPwd := TC2ConvSBS.BytesOf(edtPassword.Text);
        s := edtSaltLength.Text;
        lenSalt := StrToInt(s);
        iter := StrToInt(edtIterations.Text);
        FParams := TC2SymParams.Create(arPwd, lenSalt, iter);
      end;
    1: // Key
      begin
        arKey := TC2Base64.Decode(edtKey.Text);
        FParams := TC2SymParams.Create(arKey, FConfig.lenIVBits);
      end;
  end;
end;

end.
