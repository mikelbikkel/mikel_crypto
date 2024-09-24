program mikel_crypto;

uses
  Vcl.Forms,
  frm_main in '..\..\source\frm_main.pas' {frmMain},
  crypto_facade in '..\..\source\crypto_facade.pas',
  UsageExamples in '..\..\source\UsageExamples.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
