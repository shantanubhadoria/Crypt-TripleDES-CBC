package Crypt::TripleDES::CBC;


use Moose;
use 5.010;
use Crypt::DES;

has cipher1 => (
    is         => 'ro',
    lazy_build => 1,
);

sub _build_cipher1 {
    my ( $self ) = @_;
    my $cipher = new Crypt::DES (
        substr($self->key,0,8)
    );
}

has cipher2 => (
    is         => 'ro',
    lazy_build => 1,
);

sub _build_cipher2 {
    my ( $self ) = @_;
    my $cipher = new Crypt::DES (
        substr($self->key,8)
    );
}

has key => (
    is => 'ro',
    required => 1,
);

has iv  => (
    is => 'ro',
    required => 1,
    default  => pack("H*","0000000000000000"),
);

sub decrypt {
    my ( $self, $ciphertext, $iv ) = @_;
    my $length = length($ciphertext);
    my $result = '';
    while($length > 8){
        my $block = substr($ciphertext,0,8);
        $ciphertext = substr($ciphertext,8);
        my $cleartext = $self->_decrypt_3des($block);
        $result .= $cleartext ^ $iv;
        $iv = $block;
        $length = length($ciphertext);
    }
    my $cleartext = $self->_decrypt_3des($ciphertext);
    $result .= $cleartext ^ $iv;
    return $result;
}

sub encrypt_3des_cbc {
    my ( $self, $cleartext, $iv ) = @_;
    my $length = length($cleartext);
    my $result = '';
    while($length > 8){
        my $block = substr($cleartext,0,8);
        $cleartext = substr($cleartext,8);
        my $ciphertext = $self->_encrypt_3des($block^$iv);
        $result .= $ciphertext;
        $iv = $ciphertext;
        $length = length($cleartext);
    }
    my $ciphertext = $self->_encrypt_3des($cleartext^$iv);
    $result .= $ciphertext;
    return $result;
}

sub _encrypt_3des {
    my ( $self, $plaintext ) = @_;
    return $self->cipher1->encrypt(
        $self->cipher2->decrypt(
            $self->cipher1->encrypt($plaintext)
        )
    );
}

sub _decrypt_3des {
    my ( $self, $ciphertext ) = @_;
    return $self->cipher1->decrypt(
        $self->cipher2->encrypt(
            $self->cipher1->decrypt($ciphertext)
        )
    );
}
