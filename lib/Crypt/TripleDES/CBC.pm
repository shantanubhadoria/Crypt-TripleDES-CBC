use strict;
use warnings;
package Crypt::TripleDES::CBC;

# PODNAME: Crypt::TripleDES::CBC
# ABSTRACT: Triple DES in CBC mode Pure implementation 
# COPYRIGHT
# VERSION

# Dependencies

use Moose;
use 5.010;
use Crypt::DES;

=attr cipher1

First Crypt::DES Cipher object generated from the key. This is built
automatically. Do not change this value from your program.

=cut

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

=attr cipher2

second Crypt::DES Cipher object generated from the key. This is built
automatically. Do not change this value from your program.

=cut

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

=attr key

Encryption Key this must be ascii packed string as shown in Synopsis.

=cut

has key => (
    is => 'ro',
    required => 1,
);

=attr iv

Initialization vector, default is a null string.

=cut

has iv  => (
    is => 'ro',
    required => 1,
    default  => pack("H*","0000000000000000"),
);

=method encrypt

Encryption Method

=cut

sub encrypt {
    my ( $self, $cleartext) = @_;
    my $length = length($cleartext);
    my $result = '';
    my $iv = $self->iv;
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

=method decrypt

Decryption method

=cut

sub decrypt {
    my ( $self, $ciphertext) = @_;
    my $length = length($ciphertext);
    my $result = '';
    my $iv = $self->iv;
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

1;

__END__

=begin wikidoc

= SYNOPSIS

  use Crypt::TripleDES::CBC;

  my $key = pack("H*"
    , "1234567890123456"
    . "7890123456789012");
  my $iv = pack("H*","0000000000000000");
  my $crypt = Crypt::TripleDES::CBC->new(
    key => $key,
    iv  => $iv,
  );

  $crypt->encrypt(pack("H*","0ABC0F2241535345631FCE"));
  $crypt->decrypt(pack("H*","0ABC0F2241535345631FCE"));

= DESCRIPTION

Most Modules on CPAN don't do a standards compliant implementation, while they
are able to decrypt what they encrypt. There are corner cases where certain
blocks of data in a chain don't decrypt properly. This is (almost)a pure perl
implementation of TripleDES in CBC mode using Crypt::DES to encrypt individual
blocks.

=end wikidoc

=cut
