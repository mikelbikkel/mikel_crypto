unit test_facade;

interface

uses
  DUnitX.TestFramework;

type

  [TestFixture]
  TTestAESEncode = class
  public
    [Test]
    procedure TestCreateFacade;
  end;

implementation

uses
  crypto_facade;

{ TTestAESEncode }

procedure TTestAESEncode.TestCreateFacade;
var
  fac: TCryptoFacade;
begin
  fac := nil;
  fac := TCryptoFacade.Create;
  Assert.IsNotNull(fac, 'Create');
  fac.Free;
end;

initialization

TDUnitX.RegisterTestFixture(TTestAESEncode);

end.
