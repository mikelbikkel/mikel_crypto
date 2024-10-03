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
    procedure FormCreate(Sender: TObject);
    procedure actGenKeyExecute(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    mCrypto: TCryptoFacade;
    mKey: TCryptoItem;
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
  ctext: TCryptoItem;
begin
  edtKey.Text := EmptyStr;
  edtSalt.Text := EmptyStr;
  edtIV.Text := EmptyStr;
  memoCypher.Lines.Clear;

  mKey := mCrypto.GenKey32;
  edtKey.Text := mKey.Enc32;
  cipher := TCryptoAES256CBC.Create(edtPassword.Text, chkSalt.Checked);
  edtKey.Text := cipher.Key.Enc32;
  edtSalt.Text := cipher.Salt.Enc32;
  edtIV.Text := cipher.iv.Enc32;

  pc := memoPlain.Lines.GetText;
  ar := TEncoding.UTF8.GetBytes(pc);
  StrDispose(pc);
  ctext := cipher.Encode(ar);
  memoCypher.Lines.Add(ctext.Enc32);
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

  mCrypto := TCryptoFacade.Create;
  rnd := mCrypto.GenRandomInt;
  ca_a.Caption := S_A_UPPER + ' - ' + S_A_LOWER + ' - ' + S_EURO + ' - ' +
    S_GAL_C + ' ] ' + IntToStr(rnd);
end;

end.
