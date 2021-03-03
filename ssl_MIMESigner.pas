unit ssl_MIMESigner;

interface

uses
  SysUtils, AnsiStrings,
  ssl_lib, ssl_err, ssl_types, ssl_const, ssl_engine,
  ssl_evp, ssl_rand, ssl_rsa, ssl_bio, ssl_pem, ssl_x509, ssl_objects, ssl_pkcs12, ssl_sk, ssl_pkcs7;

type
  PCharacter = PAnsiChar;
  Caracter = AnsiChar;

  TEncoding = (auto, PEM, DER, SMIME, NETSCAPE, PKCS12);

  EOpenSSL = class(Exception)
  public
    OpenSSLError: Integer;
    OpenSSLErrorMessage: String;
    constructor Create(Msg: String);
  end;

  TKeyPairGenerator = class
  private
    fKeyLength: Word;
    fPassword: String;
    fPrivateKeyFile, fPublicKeyFile: TFileName;
    fSeedFile: TFileName;
  protected
    procedure fSetKeyLength(l: Word);
  public
    constructor Create;
    procedure KeyFileNames(KeyPairNames: string); overload;
    procedure KeyFileNames(PrivateKeyName, PublicKeyName: TFileName); overload;
    procedure GenerateRSA;
    property KeyLength: Word read fKeyLength write fSetKeyLength default 1024;
    property Password: string write fPassword;
    property SeedFile: TFileName read fSeedFile write fSeedFile;
  end;

  TX509Certificate = class
  private
    function getDN(pDn: PX509_NAME): String;
    function getTime(asn1_time: PASN1_TIME): TDateTime;
  protected
    constructor Create(pCert: PX509); overload;
    function getIssuer: String;
    function getSubject: String;
    function getNotBefore: TDateTime;
    function getNotAfter: TDateTime;
    function getSerialNumber: String;
    function VerifyCalback(ok: Integer; ctx: PX509_STORE_CTX): Integer;
  public
    fCertificate: PX509;
    constructor Create; overload;
    destructor Destroy; override;
    property Issuer: String read getIssuer;
    property Subject: String read getSubject;
    property SerialNumber: String read getSerialNumber;
    property NotBefore: TDateTime read getNotBefore;
    property NotAfter: TDateTime read getNotAfter;
    function IsTrusted(CACertificate: array of TX509Certificate): Boolean; overload;
    function IsTrusted(CACertificate: TX509Certificate): Boolean; overload;
    function IsExpired: Boolean;
    function Text: String;
    procedure LoadFromFile(FileName: string); overload;
    procedure LoadFromFile(FileName: string; Encoding: TEncoding); overload;
    function AsBase64(): String;
  end;

  TX509CertificateArray = array of TX509Certificate;

  TPKCS7 = class
  private
    fEncoding: TEncoding;
    fPkcs7: PPKCS7;
    fCerts: PSTACK_OFX509;
    fDetachedData: PBIO;
  protected
    function countCerts: Integer;
    function getCert(i: Integer): TX509Certificate;
  public
    constructor Create;
    destructor Destroy; override;
    property Encoding: TEncoding read fEncoding write fEncoding default auto;
    property CountCertificate: Integer read countCerts;
    property Certificate[Index: Integer]: TX509Certificate read getCert;
    procedure Open(FileName: string);
    procedure Save(FileName: String); overload;
    procedure Save(FileName: String; Encoding: TEncoding); overload;
    procedure SaveContent(FileName: String);
    function VerifyData: Boolean; overload;
    function VerifyData(Content: Pointer): Boolean; overload;
  end;

  TMIMESigner = class
  private
    fCertificate: PX509;
    fOtherCertificates: PSTACK_OF;
    fKey: PEVP_PKEY;
  public
    function SignText(const Text: WideString): WideString;
    procedure LoadPrivateKey(const PrivateKeyPath: TFileName; const KeyPassword: WideString);
    procedure LoadCertificate(const CertificatePath: TFileName);
    constructor Create(const LibPath: String = '');
  end;

implementation

function ToChar(Str: String): PAnsiChar; overload;
begin
  Result := PAnsiChar(AnsiString(Str));
end;

function ToChar(Str: Pointer): PAnsiChar; overload;
begin
  Result := PAnsiChar(Str);
end;

function GetErrorMessage: String;
var
  ErrMsg: array [0 .. 160] of Caracter;
begin
  ERR_error_string(ERR_get_error, @ErrMsg);
  Result := String(AnsiStrings.StrPas(PAnsiChar(@ErrMsg)));
end;

constructor EOpenSSL.Create(Msg: string);
begin
  inherited Create(Msg);
  OpenSSLError := ERR_get_error;
  OpenSSLErrorMessage := GetErrorMessage;
end;

function cvOpenSSLEncoding(Encoding: TEncoding): Integer;
begin
  Result := FORMAT_UNDEF;
  case Encoding of
    DER:
      Result := FORMAT_ASN1;
    PEM:
      Result := FORMAT_PEM;
    NETSCAPE:
      Result := FORMAT_NETSCAPE;
    PKCS12:
      Result := FORMAT_PKCS12;
  end;
end;

constructor TKeyPairGenerator.Create;
var
  TmpDir: string;
  TmpFile: TSearchRec;
begin
{$WARN SYMBOL_PLATFORM OFF}
  fKeyLength := 1024;
  fPassword := EmptyStr;
  TmpDir := GetEnvironmentVariable('TEMP');
  if FindFirst(TmpDir + '\*', faReadOnly and faHidden and faSysFile and faArchive, TmpFile) = 0 then
    fSeedFile := TmpFile.Name;
  FindClose(TmpFile);
{$WARN SYMBOL_PLATFORM ON}
end;

// TODO: checking key length and throw exception
procedure TKeyPairGenerator.fSetKeyLength(l: Word);
begin
  fKeyLength := l;
end;

procedure TKeyPairGenerator.KeyFileNames(KeyPairNames: string);
begin
  KeyFileNames(KeyPairNames + '.key', KeyPairNames + '.pub');
end;

procedure TKeyPairGenerator.KeyFileNames(PrivateKeyName, PublicKeyName: TFileName);
begin
  fPrivateKeyFile := PrivateKeyName;
  fPublicKeyFile := PublicKeyName;
end;

procedure TKeyPairGenerator.GenerateRSA;
var
  RSA: pRSA;
  PrivateKeyOut, PublicKeyOut, ErrMsg: PBIO;
  Buff: array [0 .. 1023] of Caracter;
  Enc: pEVP_CIPHER;
begin
  if (fPrivateKeyFile = '') or (fPublicKeyFile = '') then
    raise EOpenSSL.Create('Key filenames must be specified.');
  if (fPassword = '') then
    raise EOpenSSL.Create('A password must be specified.');
  ERR_load_crypto_strings;
  OpenSSL_add_all_ciphers;
  Enc := EVP_des_ede3_cbc;
  // Load a pseudo random file
  RAND_load_file(ToChar(fSeedFile), -1);
  ErrMsg := nil;
  RSA := RSA_generate_key(fKeyLength, RSA_F4, nil, ErrMsg);
  if RSA = nil then
  begin
    BIO_reset(ErrMsg);
    BIO_read(ErrMsg, @Buff, 1024);
    raise EOpenSSL.Create(String(ToChar(@Buff)));
  end;
  PrivateKeyOut := BIO_new(BIO_s_file());
  BIO_write_filename(PrivateKeyOut, ToChar(fPrivateKeyFile));
  PublicKeyOut := BIO_new(BIO_s_file());
  BIO_write_filename(PublicKeyOut, ToChar(fPublicKeyFile));
  PEM_write_bio_RSAPrivateKey(PrivateKeyOut, RSA, Enc, nil, 0, nil, ToChar(fPassword));
  PEM_write_bio_RSAPublicKey(PublicKeyOut, RSA);
  if RSA <> nil then
    RSA_free(RSA);
  if PrivateKeyOut <> nil then
    BIO_free_all(PrivateKeyOut);
  if PublicKeyOut <> nil then
    BIO_free_all(PublicKeyOut);
end;

constructor TX509Certificate.Create;
begin
  fCertificate := nil;
end;

constructor TX509Certificate.Create(pCert: PX509);
begin
  fCertificate := pCert;
end;

destructor TX509Certificate.Destroy;
begin
  if fCertificate <> nil then
    X509_free(fCertificate);
end;

function TX509Certificate.getDN(pDn: PX509_NAME): String;
var
  buffer: array [0 .. 1023] of Caracter;
begin
  X509_NAME_oneline(pDn, @buffer, SizeOf(buffer));
  Result := String(AnsiStrings.StrPas(PAnsiChar(@buffer)));
end;

// Extract a ASN1 time
function TX509Certificate.getTime(asn1_time: PASN1_TIME): TDateTime;
var
  buffer: array [0 .. 31] of Caracter;
  tz, Y, M, D, h, n, s: Word;
  function Char2Int(D, u: Caracter): Integer;
  begin
    if (D < '0') or (D > '9') or (u < '0') or (u > '9') then
      raise EOpenSSL.Create('Invalid ASN1 date format (invalid char).');
    Result := (Ord(D) - Ord('0')) * 10 + Ord(u) - Ord('0');
  end;

begin
  if (asn1_time._type <> V_ASN1_UTCTIME) and (asn1_time._type <> V_ASN1_GENERALIZEDTIME) then
    raise EOpenSSL.Create('Invalid ASN1 date format.');
  tz := 0;
  Y := 0;
  M := 0;
  D := 0;
  h := 0;
  n := 0;
  s := 0;
  AnsiStrings.StrLCopy(PAnsiChar(@buffer), asn1_time.data, asn1_time.Length);
  if asn1_time._type = V_ASN1_UTCTIME then
  begin
    if asn1_time.Length < 10 then
      raise EOpenSSL.Create('Invalid ASN1 UTC date format (too short).');
    Y := Char2Int(buffer[0], buffer[1]);
    if Y < 50 then
      Y := Y + 100;
    Y := Y + 1900;
    M := Char2Int(buffer[2], buffer[3]);
    D := Char2Int(buffer[4], buffer[5]);
    h := Char2Int(buffer[6], buffer[7]);
    n := Char2Int(buffer[8], buffer[9]);
    if (buffer[10] >= '0') and (buffer[10] <= '9')
      and (buffer[11] >= '0') and (buffer[11] <= '9') then
      s := Char2Int(buffer[10], buffer[11]);
    if buffer[asn1_time.Length - 1] = 'Z' then
      tz := 1;
  end
  else if asn1_time._type = V_ASN1_GENERALIZEDTIME then
  begin
    if asn1_time.Length < 12 then
      raise EOpenSSL.Create('Invalid ASN1 generic date format (too short).');
    Y := Char2Int(buffer[0], buffer[1]) * 100 + Char2Int(buffer[2], buffer[3]);;
    M := Char2Int(buffer[4], buffer[5]);
    D := Char2Int(buffer[6], buffer[7]);
    h := Char2Int(buffer[8], buffer[9]);
    n := Char2Int(buffer[10], buffer[11]);
    if (buffer[12] >= '0') and (buffer[12] <= '9')
      and (buffer[13] >= '0') and (buffer[13] <= '9') then
      s := Char2Int(buffer[12], buffer[13]);
    if buffer[asn1_time.Length - 1] = 'Z' then
      tz := 1;
  end;
  Result := EncodeDate(Y, M, D) + EncodeTime(h, n, s, tz);
end;

function TX509Certificate.getIssuer: String;
begin
  Result := getDN(X509_get_issuer_name(fCertificate));
end;

function TX509Certificate.getSubject: String;
begin
  Result := getDN(X509_get_subject_name(fCertificate));
end;

function TX509Certificate.getSerialNumber: String;
var
  buffer: array [0 .. 20] of Caracter;
  v: PASN1_INTEGER;
begin
  v := X509_get_serialNumber(fCertificate);
  AnsiStrings.StrLCopy(PAnsiChar(@buffer), v.data, v.Length);
  Result := String(buffer);
end;

function TX509Certificate.getNotBefore: TDateTime;
begin
  Result := getTime(X509_get_notBefore(fCertificate));
end;

function TX509Certificate.getNotAfter: TDateTime;
begin
  Result := getTime(X509_get_notAfter(fCertificate));
end;

function TX509Certificate.Text: String;
var
  certOut: PBIO;
  Buff: PCharacter;
  BuffSize: Integer;
begin
  Result := '';
  certOut := BIO_new(BIO_s_mem);
  X509_print(certOut, fCertificate);
  BuffSize := BIO_pending(certOut);
  GetMem(Buff, BuffSize + 1);
  BIO_read(certOut, Buff, BuffSize);
  Result := String(AnsiStrings.StrPas(Buff));
  FreeMem(Buff);
  BIO_free(certOut);
end;

procedure TX509Certificate.LoadFromFile(FileName: string);
begin
  LoadFromFile(FileName, auto);
end;

// Function created by Luis Carrasco (Bambu Code SA de CV) to obtain the certificate as base64 encoded format.
function TX509Certificate.AsBase64(): String;
var
  bioOut: PBIO;
  buffer: array [0 .. 4096] of Caracter;
  Res: String;
begin
  // This code was translated from x509.c from the OpenSSL source code
  Res := '';
  buffer := '';
  bioOut := nil;
  try
    OBJ_create(ToChar('2.99999.3'), ToChar('SET.ex3'), ToChar('SET x509v3 extension 3'));
    bioOut := BIO_new(BIO_s_mem);
    // We obtain the certificate in base64 encoded format into the bioOut pointer
    if PEM_write_bio_X509(bioOut, fCertificate) = 1 then
      BIO_read(bioOut, @buffer, SizeOf(buffer))
    else
      Res := '';
  finally
    OBJ_cleanup();
    BIO_free_all(bioOut);
  end;
  Result := String(AnsiStrings.StrPas(buffer));
end;

procedure TX509Certificate.LoadFromFile(FileName: string; Encoding: TEncoding);
var
  certfile: PBIO;
  p12: pPKCS12;
  a: PPEVP_PKEY;
  c: PPX509;
  ca: PSTACK_OFX509;
begin
  if not(Encoding in [auto, DER, PEM, NETSCAPE, PKCS12]) then
    raise EOpenSSL.Create('Bad certificate encoding.');
  certfile := BIO_new(BIO_s_file());
  if certfile = nil then
    raise EOpenSSL.Create('Error creating BIO.');
  // Returns 0 for failure. Ref: http://www.openssl.org/docs/crypto/BIO_s_file.html
  if BIO_read_filename(certfile, PAnsiChar(AnsiString((FileName)))) = 0 then
    raise Exception.Create('Unable to read certificate file');
  if (Encoding = auto) or (Encoding = DER) then
  begin
    fCertificate := d2i_X509_bio(certfile, nil);
    if (Encoding = auto) and (fCertificate = nil) then
      BIO_reset(certfile);
  end;
  if ((Encoding = auto) and (fCertificate = nil)) or (Encoding = PEM) then
  begin
    fCertificate := PEM_read_bio_X509_AUX(certfile, c, nil, nil);
    if (Encoding = auto) and (fCertificate = nil) then
      BIO_reset(certfile);
  end;
  if ((Encoding = auto) and (fCertificate = nil)) or (Encoding = PKCS12) then
  begin
    p12 := d2i_PKCS12_bio(certfile, nil);
    if p12 <> nil then
    begin
      a := nil;
      ca := nil;
      PKCS12_parse(p12, nil, a, c, ca);
      fCertificate := @c;
      PKCS12_free(p12);
    end;
  end;
  BIO_free(certfile);
  if fCertificate = nil then
    raise EOpenSSL.Create('Unable to read certificate from file ' + FileName + '.');
end;

function TX509Certificate.VerifyCalback(ok: Integer; ctx: PX509_STORE_CTX): Integer;
begin
  if ok = 0 then
    ok := 1;
  Result := ok;
end;

function TX509Certificate.IsTrusted(CACertificate: array of TX509Certificate): Boolean;
var
  cert_ctx: PX509_STORE;
  csc: PX509_STORE_CTX;
  uchain: PSTACK_OFX509;
  i, verify: Integer;
begin
  cert_ctx := X509_STORE_new();
  if cert_ctx = nil then
    raise EOpenSSL.Create('Error creating X509_STORE.');
  cert_ctx.verify_cb := nil;
  // Load CA certificates
  for i := 0 to High(CACertificate) do
  begin
    if X509_STORE_add_cert(cert_ctx, CACertificate[i].fCertificate) = 0 then
      raise EOpenSSL.Create('Unable to store X.509 cetrtificate.');
  end;
  // Load untrustesd certificate
  uchain := sk_new_null;
  sk_push(uchain, fCertificate);
  // Prepare certificate
  csc := X509_STORE_CTX_new;
  if csc = nil then
    raise EOpenSSL.Create('Error creating X509_STORE_CTX.');
  X509_STORE_CTX_init(csc, cert_ctx, fCertificate, uchain);
  verify := X509_verify_cert(csc);
  X509_STORE_CTX_free(csc);
  sk_free(uchain);
  X509_STORE_free(cert_ctx);
  Result := verify = 1;
end;

function TX509Certificate.IsTrusted(CACertificate: TX509Certificate): Boolean;
begin
  Result := false;
end;

function TX509Certificate.IsExpired: Boolean;
var
  now: TDateTime;
begin
  now := Time;
  Result := (NotBefore <= now) and (NotAfter >= now);
end;

constructor TPKCS7.Create;
begin
  fEncoding := auto;
  fPkcs7 := nil;
  fCerts := nil;
  fDetachedData := nil;
end;

destructor TPKCS7.Destroy;
begin
  if fDetachedData <> nil then
    BIO_free(fDetachedData);
  if fPkcs7 <> nil then
    PKCS7_free(fPkcs7);
end;

function TPKCS7.countCerts: Integer;
begin
  Result := sk_num(fCerts);
end;

function TPKCS7.getCert(i: Integer): TX509Certificate;
begin
  Result := TX509Certificate.Create(sk_value(fCerts, i));
end;

procedure TPKCS7.Open(FileName: string);
var
  p7file: PBIO;
  objectType: Integer;
begin
  p7file := BIO_new(BIO_s_file());
  if p7file = nil then
    raise EOpenSSL.Create('Unable to create a file handle.');
  BIO_read_filename(p7file, ToChar(FileName));
  if (fEncoding = auto) or (fEncoding = DER) then
  begin
    fPkcs7 := d2i_PKCS7_bio(p7file, nil);
    if (fPkcs7 = nil) and (fEncoding = auto) then
      BIO_reset(p7file);
  end;
  if ((fPkcs7 = nil) and (fEncoding = auto)) or (fEncoding = PEM) then
  begin
    fPkcs7 := PEM_read_bio_PKCS7(p7file, nil, nil, nil);
    if (fPkcs7 = nil) and (fEncoding = auto) then
      BIO_reset(p7file);
  end;
  if ((fPkcs7 = nil) and (fEncoding = auto)) or (fEncoding = SMIME) then
    fPkcs7 := SMIME_read_PKCS7(p7file, Pointer(fDetachedData));
  if fPkcs7 = nil then
    raise EOpenSSL.Create('Unable to read PKCS7 file');
  if p7file <> nil then
    BIO_free(p7file);
  objectType := OBJ_obj2nid(fPkcs7._type);
  case objectType of
    NID_pkcs7_signed:
      fCerts := fPkcs7.sign.cert;
    NID_pkcs7_signedAndEnveloped:
      fCerts := fPkcs7.signed_and_enveloped.cert;
  end;
end;

procedure TPKCS7.Save(FileName: String);
begin
  Save(FileName, DER);
end;

procedure TPKCS7.Save(FileName: String; Encoding: TEncoding);
var
  pkcs7file: PBIO;
  Result: Integer;
begin
  Result := 0;
  if not(Encoding in [DER, PEM]) then
    raise EOpenSSL.Create('Invalid output format.');
  pkcs7file := BIO_new(BIO_s_file());
  if BIO_write_filename(pkcs7file, ToChar(FileName)) <= 0 then
    raise EOpenSSL.Create('Error creating output file.');
  if Encoding = DER then
    Result := i2d_PKCS7_bio(pkcs7file, fPkcs7);
  if Encoding = PEM then
    Result := PEM_write_bio_PKCS7(pkcs7file, fPkcs7);
  if pkcs7file <> nil then
    BIO_free(pkcs7file);
  if Result = 0 then
    raise EOpenSSL.Create('Error writing output file.');
end;

procedure TPKCS7.SaveContent(FileName: String);
var
  p7bio, contentfile: PBIO;
  sinfos: PSTACK_OF_PKCS7_SIGNER_INFO;
  i: Integer;
  buffer: array [0 .. 4096] of Caracter;
begin
  if fPkcs7 = nil then
    raise EOpenSSL.Create('No PKCS7 content.');
  if OBJ_obj2nid(fPkcs7._type) <> NID_pkcs7_signed then
    raise EOpenSSL.Create('Wrong PKCS7 format.');
  if (PKCS7_get_detached(fPkcs7) <> nil)
    and (fDetachedData = nil) then
    raise EOpenSSL.Create('PKCS7 has no content.');
  sinfos := PKCS7_get_signer_info(fPkcs7);
  if (sinfos = nil) or (sk_num(sinfos) = 0) then
    raise EOpenSSL.Create('No signature data.');
  contentfile := BIO_new(BIO_s_file());
  if BIO_write_filename(contentfile, ToChar(FileName)) <= 0 then
    raise EOpenSSL.Create('Error creating output file.');
  p7bio := PKCS7_dataInit(fPkcs7, fDetachedData);
  repeat
    i := BIO_read(p7bio, @buffer, SizeOf(buffer));
    if i > 0 then
      BIO_write(contentfile, @buffer, i);
  until i <= 0;
  if fDetachedData <> nil then
    BIO_pop(p7bio);
  BIO_free_all(p7bio);
  BIO_free(contentfile);
end;

// Return true for data integrity check for nodetachted PKCS7
function TPKCS7.VerifyData: Boolean;
begin
  Result := VerifyData(nil);
end;

// Return true for data integrity check for detachted PKCS7
function TPKCS7.VerifyData(Content: Pointer): Boolean;
var
  p7bio, tmpout: PBIO;
  sinfos: PSTACK_OF_PKCS7_SIGNER_INFO;
  si: pPKCS7_SIGNER_INFO;
  signers: PSTACK_OFX509;
  signer: PX509;
  i: Integer;
  buffer: array [0 .. 4096] of Caracter;
begin
  Result := true;
  if fPkcs7 = nil then
    raise EOpenSSL.Create('No PKCS7 content.');
  if OBJ_obj2nid(fPkcs7._type) <> NID_pkcs7_signed then
    raise EOpenSSL.Create('Wrong PKCS7 format.');
  if (PKCS7_get_detached(fPkcs7) <> nil) and (fDetachedData = nil) then
    raise EOpenSSL.Create('PKCS7 has no content.');
  sinfos := PKCS7_get_signer_info(fPkcs7);
  if (sinfos = nil) or (sk_num(sinfos) = 0) then
    raise EOpenSSL.Create('No signature data.');
  signers := PKCS7_get0_signers(fPkcs7, nil, 0);
  p7bio := PKCS7_dataInit(fPkcs7, fDetachedData);
  tmpout := BIO_new(BIO_s_mem());
  repeat
    i := BIO_read(p7bio, @buffer, SizeOf(buffer));
    if i > 0 then
      BIO_write(tmpout, @buffer, i);
  until i <= 0;
  for i := 0 to Pred(sk_num(sinfos)) do
  begin
    si := sk_value(sinfos, i);
    signer := sk_value(signers, i);
    if PKCS7_signatureVerify(p7bio, fPkcs7, si, signer) <= 0 then
    begin
      Result := false;
      break;
    end;
  end;
  if fDetachedData <> nil then
    BIO_pop(p7bio);
  BIO_free_all(p7bio);
  sk_free(signers);
  if (fDetachedData <> nil) then
    BIO_reset(fDetachedData);
end;

{ TMIMESigner }

procedure TMIMESigner.LoadPrivateKey(const PrivateKeyPath: TFileName; const KeyPassword: WideString);
var
  keyfile: PBIO;
  pw: PAnsiChar;
  a: PPEVP_PKEY; // Because PEM_read_bio_PrivateKey uses parameters by-reference
begin
  a := nil;
  keyfile := BIO_new(BIO_s_file());
  BIO_read_filename(keyfile, ToChar(PrivateKeyPath));
  if Length(KeyPassword) > 0 then
    pw := ToChar(KeyPassword)
  else
    pw := nil;
  fKey := PEM_read_bio_PrivateKey(keyfile, a, nil, pw);
  if fKey = nil then
    raise EOpenSSL.Create('Unable to read private key. ' + GetErrorMessage);
end;

procedure TMIMESigner.LoadCertificate(const CertificatePath: TFileName);
var
  certfile: PBIO;
  c: PPX509; // Because PEM_read_bio_X509_AUX uses parameters by-reference
begin
  c := nil;
  certfile := BIO_new(BIO_s_file());
  BIO_ctrl(certfile, BIO_C_SET_FILENAME, BIO_CLOSE or BIO_FP_READ, ToChar(CertificatePath));
  fCertificate := PEM_read_bio_X509_AUX(certfile, c, nil, nil);
  if fCertificate = nil then
    raise EOpenSSL.Create('Unable to read certificate. ' + GetErrorMessage);
end;

function TMIMESigner.SignText(const Text: WideString): WideString;
var
  P7: PPKCS7;
  MsgIn, MsgOut: PBIO;
  Buff: PAnsiChar;
  BuffSize: Integer;
begin
  if not Assigned(fKey) then
    raise EOpenSSL.Create('Private key is required.');
  if not Assigned(fCertificate) then
    raise EOpenSSL.Create('Signer certificate is required.');
  MsgIn := BIO_new_mem_buf(ToChar(Text), -1);
  MsgOut := BIO_new(BIO_s_mem);
  P7 := PKCS7_sign(fCertificate, fKey, fOtherCertificates, MsgIn, PKCS7_BINARY);
  BIO_reset(MsgIn);
  SMIME_write_PKCS7(MsgOut, P7, MsgIn, PKCS7_TEXT);
  BuffSize := BIO_pending(MsgOut);
  GetMem(Buff, Succ(BuffSize));
  try
    BIO_read(MsgOut, Buff, BuffSize);
    Result := WideString(Buff);
  finally
    FreeMem(Buff);
  end;
end;

constructor TMIMESigner.Create(const LibPath: String);
begin
  if Length(LibPath) > 0 then
    SSL_C_LIB := AnsiString(LibPath);
  SSL_InitERR;
  SSL_InitBIO;
  SSL_InitEVP;
  SSL_InitPEM;
  SSL_InitOBJ;
  SSL_InitRSA;
  SSL_InitX509;
  SSL_InitPKCS7;
  fKey := nil;
  fCertificate := nil;
  fOtherCertificates := nil;
  ERR_load_crypto_strings;
  OpenSSL_add_all_digests;
  OpenSSL_add_all_ciphers;
end;

end.
