object frmMain: TfrmMain
  Left = 0
  Top = 0
  Caption = 'frmMain'
  ClientHeight = 660
  ClientWidth = 628
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  OnClose = FormClose
  OnCreate = FormCreate
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
    Top = 64
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
    Top = 64
    Width = 23
    Height = 15
    Caption = 'ca_a'
  end
  object lblPassword: TLabel
    Left = 209
    Top = 211
    Width = 56
    Height = 15
    Caption = 'Password: '
  end
  object Label3: TLabel
    Left = 41
    Top = 211
    Width = 99
    Height = 15
    Caption = 'Crypto Algorithm: '
  end
  object Label4: TLabel
    Left = 48
    Top = 307
    Width = 81
    Height = 15
    Caption = 'Generated key: '
  end
  object Label5: TLabel
    Left = 48
    Top = 336
    Width = 73
    Height = 15
    Caption = 'Generated IV: '
  end
  object Label6: TLabel
    Left = 48
    Top = 278
    Width = 78
    Height = 15
    Caption = 'Generated salt:'
  end
  object Label7: TLabel
    Left = 40
    Top = 374
    Width = 61
    Height = 15
    Caption = 'Cipher text:'
  end
  object Button1: TButton
    Left = 340
    Top = 16
    Width = 93
    Height = 33
    Action = actGenKey
    TabOrder = 0
  end
  object edtKey: TEdit
    Left = 144
    Top = 304
    Width = 448
    Height = 23
    ReadOnly = True
    TabOrder = 1
  end
  object edtPassword: TEdit
    Left = 209
    Top = 232
    Width = 175
    Height = 23
    TabOrder = 2
    Text = 'Geheim74586mfgbk%$$#@F'
  end
  object chkSalt: TCheckBox
    Left = 473
    Top = 235
    Width = 97
    Height = 17
    Caption = 'Use salt'
    Checked = True
    State = cbChecked
    TabOrder = 3
  end
  object cmbCryptoAlgo: TComboBox
    Left = 41
    Top = 232
    Width = 145
    Height = 23
    Style = csDropDownList
    ItemIndex = 1
    TabOrder = 4
    Text = 'aes-192-cbc'
    Items.Strings = (
      'aes-128-cbc'
      'aes-192-cbc'
      'aes-256-cbc')
  end
  object edtIV: TEdit
    Left = 144
    Top = 333
    Width = 448
    Height = 23
    ReadOnly = True
    TabOrder = 5
  end
  object edtSalt: TEdit
    Left = 144
    Top = 275
    Width = 240
    Height = 23
    TabOrder = 6
  end
  object memoPlain: TMemo
    Left = 41
    Top = 104
    Width = 552
    Height = 73
    Lines.Strings = (
      'To be or not to be'
      'That is the question. Like it or not.')
    TabOrder = 7
  end
  object memoCypher: TMemo
    Left = 40
    Top = 395
    Width = 553
    Height = 70
    TabOrder = 8
  end
  object memoDecrypt: TMemo
    Left = 40
    Top = 512
    Width = 552
    Height = 73
    Lines.Strings = (
      'memoDecrypt')
    TabOrder = 9
  end
  object btnDecrypt: TButton
    Left = 456
    Top = 17
    Width = 75
    Height = 31
    Action = actDecrypt
    TabOrder = 10
  end
  object chkUse2: TCheckBox
    Left = 385
    Top = 81
    Width = 97
    Height = 17
    Caption = 'UseCrypto 2'
    TabOrder = 11
  end
  object edtMacSend: TEdit
    Left = 136
    Top = 183
    Width = 456
    Height = 23
    TabOrder = 12
    Text = 'edtMacSend'
  end
  object edtMacReceive: TEdit
    Left = 136
    Top = 608
    Width = 456
    Height = 23
    TabOrder = 13
    Text = 'edtMacReceive'
  end
  object alMain: TActionList
    Left = 544
    Top = 24
    object actGenKey: TAction
      Caption = 'Encrypt'
      OnExecute = actGenKeyExecute
    end
    object actDecrypt: TAction
      Caption = 'Decrypt'
      OnExecute = actDecryptExecute
    end
  end
end
