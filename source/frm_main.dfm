object frmMain: TfrmMain
  Left = 0
  Top = 0
  Caption = 'frmMain'
  ClientHeight = 563
  ClientWidth = 837
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  OnClose = FormClose
  OnCreate = FormCreate
  OnShow = FormShow
  TextHeight = 15
  object Label1: TLabel
    Left = 24
    Top = 16
    Width = 95
    Height = 15
    Caption = 'Plaintext alphabet'
  end
  object Label2: TLabel
    Left = 24
    Top = 37
    Width = 104
    Height = 15
    Caption = 'Ciphertext alphabet'
  end
  object pa_a: TLabel
    Left = 176
    Top = 16
    Width = 8
    Height = 15
    Caption = 'A'
  end
  object ca_a: TLabel
    Left = 176
    Top = 37
    Width = 23
    Height = 15
    Caption = 'ca_a'
  end
  object lblPassword: TLabel
    Left = 398
    Top = 164
    Width = 56
    Height = 15
    Caption = 'Password: '
  end
  object Label3: TLabel
    Left = 32
    Top = 164
    Width = 99
    Height = 15
    Caption = 'Crypto Algorithm: '
  end
  object Label4: TLabel
    Left = 32
    Top = 283
    Width = 81
    Height = 15
    Caption = 'Generated key: '
  end
  object Label7: TLabel
    Left = 32
    Top = 407
    Width = 61
    Height = 15
    Caption = 'Cipher text:'
  end
  object Label8: TLabel
    Left = 127
    Top = 243
    Width = 102
    Height = 15
    Caption = 'Key length [in bits]:'
  end
  object Label9: TLabel
    Left = 361
    Top = 230
    Width = 89
    Height = 15
    Caption = 'Salt length [bits]:'
  end
  object Label10: TLabel
    Left = 398
    Top = 196
    Width = 52
    Height = 15
    Caption = 'Iterations:'
  end
  object Label11: TLabel
    Left = 33
    Top = 201
    Width = 99
    Height = 15
    Caption = 'HMAC Algorithm: '
  end
  object Label5: TLabel
    Left = 30
    Top = 336
    Width = 64
    Height = 15
    Caption = 'MAC send:  '
  end
  object Label6: TLabel
    Left = 33
    Top = 365
    Width = 76
    Height = 15
    Caption = 'MAC receive:  '
  end
  object Button1: TButton
    Left = 340
    Top = 16
    Width = 93
    Height = 33
    Action = actEncrypt
    TabOrder = 0
  end
  object edtKey: TEdit
    Left = 128
    Top = 280
    Width = 448
    Height = 23
    ReadOnly = True
    TabOrder = 1
  end
  object edtPassword: TEdit
    Left = 470
    Top = 164
    Width = 175
    Height = 23
    TabOrder = 2
    Text = 'Geheim74586mfgbk%$$#@F'
  end
  object cmbCryptoAlgo: TComboBox
    Left = 137
    Top = 164
    Width = 184
    Height = 23
    Style = csDropDownList
    ItemIndex = 1
    TabOrder = 3
    Text = 'aes-192-cbc'
    Items.Strings = (
      'aes-128-cbc'
      'aes-192-cbc'
      'aes-256-cbc')
  end
  object memoPlain: TMemo
    Left = 24
    Top = 64
    Width = 552
    Height = 73
    Lines.Strings = (
      'To be or not to be'
      'That is the question. Like it or not.')
    TabOrder = 4
  end
  object memoCypher: TMemo
    Left = 32
    Top = 428
    Width = 553
    Height = 45
    TabOrder = 5
  end
  object memoDecrypt: TMemo
    Left = 33
    Top = 504
    Width = 552
    Height = 41
    Lines.Strings = (
      'memoDecrypt')
    TabOrder = 6
  end
  object btnDecrypt: TButton
    Left = 456
    Top = 17
    Width = 75
    Height = 31
    Action = actDecrypt
    TabOrder = 7
  end
  object edtMacSend: TEdit
    Left = 128
    Top = 333
    Width = 456
    Height = 23
    TabOrder = 8
    Text = 'edtMacSend'
  end
  object edtMacReceive: TEdit
    Left = 129
    Top = 362
    Width = 456
    Height = 23
    TabOrder = 9
    Text = 'edtMacReceive'
  end
  object cmbKeyLength: TComboBox
    Left = 232
    Top = 240
    Width = 89
    Height = 23
    TabOrder = 10
    Text = 'cmbKeyLength'
  end
  object edtSaltLength: TEdit
    Left = 470
    Top = 227
    Width = 52
    Height = 23
    MaxLength = 2
    NumbersOnly = True
    TabOrder = 11
    Text = '64'
  end
  object edtIterations: TEdit
    Left = 470
    Top = 193
    Width = 52
    Height = 23
    TabOrder = 12
    Text = '12000'
  end
  object cmbHMAC: TComboBox
    Left = 138
    Top = 193
    Width = 183
    Height = 23
    TabOrder = 13
    Text = 'hmac'
  end
  object rgKeySource: TRadioGroup
    Left = 640
    Top = 201
    Width = 145
    Height = 105
    Caption = 'Key source'
    ItemIndex = 0
    Items.Strings = (
      'Password'
      'Random key')
    TabOrder = 14
  end
  object btnGenerateKey: TButton
    Left = 664
    Top = 30
    Width = 97
    Height = 32
    Action = actGenerateKey
    TabOrder = 15
  end
  object alMain: TActionList
    Left = 600
    Top = 24
    object actEncrypt: TAction
      Caption = 'Encrypt'
      OnExecute = actEncryptExecute
    end
    object actDecrypt: TAction
      Caption = 'Decrypt'
      OnExecute = actDecryptExecute
    end
    object actGenerateKey: TAction
      Caption = 'Generate Key'
      OnExecute = actGenerateKeyExecute
    end
  end
end
