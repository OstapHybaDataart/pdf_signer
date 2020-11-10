import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from sign import SignedData


def sign_pdf(*, in_pdf_file, out_pdf_file, pkcs12_file, pass_phrase, email,
            signaturebox, sigfield):
    singing_parameters = {
        'contact': email,
        'location': 'Ukraine, Lviv',
        # 'signingdate': datetime.datetime.utcnow().strftime(
        #     "%Y%m%d%H%M%S+00'00'"),
        'signingdate': datetime.datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S+00'00'"),
        'reason': 'DocumentSignReason',
        'aligned': 0,
        'sigflags': 3,
        'sigflagsft': 132,
        'sigpage': 0,
        'sigbutton': False,
        'sigfield': sigfield,
        'sigandcertify': True,
        'signaturebox': signaturebox,
        'signature': 'DocumentSignedManually',
        'signature_img': './logo.png',
        'password': 123456,
    }

    with open(in_pdf_file, 'rb') as f:
        pdf_file = f.read()

    key, certificate, other_certificates = _extract_pkcs12(
        pkcs12_file, pass_phrase)

    signer = SignedData()

    sign_data = signer.sign(
        datau=pdf_file,
        udct=singing_parameters,
        key=key,
        cert=certificate,
        othercerts=other_certificates,
        algomd='sha256',
        hsm=None,
        timestampurl=None,
        timestampcredentials=None,
    )

    with open(out_pdf_file, 'wb') as fp:
        fp.write(pdf_file)
        fp.write(sign_data)


def _extract_pkcs12(pkcs12_file, pass_phrase):
    with open(pkcs12_file, 'rb') as fp:
        pkcs12_data = pkcs12.load_key_and_certificates(
            fp.read(), pass_phrase, backends.default_backend()
        )
    return pkcs12_data[0], pkcs12_data[1], pkcs12_data[2]


if __name__ == '__main__':

    sign_pdf(
        in_pdf_file='./pdf_files/hw.pdf',
        out_pdf_file='./pdf_files/hw_signed.pdf',
        pkcs12_file='./keys/keystore.p12',
        pass_phrase=b'123456',
        email='admin1@admin.com',
        signaturebox=(370, 840, 570, 540),
        sigfield='Signature1'
    )
    sign_pdf(
        in_pdf_file='./pdf_files/hw_signed.pdf',
        out_pdf_file='./pdf_files/hw_signed_2.pdf',
        pkcs12_file='./keys/keystore.p12',
        pass_phrase=b'123456',
        email='admin2@admin.com',
        signaturebox=(370, 840, 570, 540),
        sigfield='Signature2',
    )

