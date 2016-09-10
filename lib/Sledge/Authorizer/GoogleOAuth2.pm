package Sledge::Authorizer::GoogleOAuth2;

use strict;
use base qw(Sledge::Authorizer Class::Data::Inheritable);

use URI;
use LWP::UserAgent;
use MIME::Base64;
use JSON;

__PACKAGE__->mk_classdata('loginlink_template');

__PACKAGE__->mk_classdata('client_id');
__PACKAGE__->mk_classdata('client_secret');
__PACKAGE__->mk_classdata('redirect_uri');

sub google_oauth2 {
    my $self  = shift;
    my $page  = shift;

    my $code = scalar $page->r->param('code');
    unless ($code) {
        $self->show_loginlink_page($page);
        return;
    }

    my $ua = LWP::UserAgent->new;
    my %param = (
        client_id       => $self->client_id,
        client_secret   => $self->client_secret,
        redirect_uri    => $self->redirect_uri,
        grant_type      => "authorization_code",
        code            => $code,
    );

    my $res = $ua->post('https://accounts.google.com/o/oauth2/token', \%param);

    unless ($res->is_success) {
        $self->show_loginlink_page($page);
        return;
    }

    my %session;
    my $payload;

    eval {
        my $content = JSON::from_json $res->content;
        my @id_token  = split /\./, $content->{id_token};

        # ref. https://github.com/bitly/oauth2_proxy/blob/51a2e4e48c5ba5557c43fc0286d1a1e8aa711cb0/providers/google.go

        $payload = JSON::from_json decode_base64($id_token[1]);

        %session = (
            access_token    => $content->{access_token},
            expires_on      => time + $content->{expires_in} - 1,
            refresh_token   => $content->{refresh_token},
            payload         => $payload,
        );
        # TODO expires_on のタイムアウト処理
    };
    if ($@) {
        $self->show_loginlink_page($page);
        return;
    }
    return ($payload->{email}, \%session);
}

sub show_loginlink_page {
    my $self = shift;
    my $page = shift;

    $page->load_template($self->loginlink_template);
    $page->r->status(401);
    $page->tmpl->param( next_url => $self->make_url );
    $page->output_content;
}

sub make_url {
    my $self = shift;

    my %form = (
        client_id       => $self->client_id,
        redirect_uri    => $self->redirect_uri,
        scope           => join(' ', qw/profile email/ ),
        response_type   => "code",
        approval_prompt => "force",
        access_type     => "offline"
    );

    my $uri = URI->new('https://accounts.google.com/o/oauth2/auth');
    $uri->query_form(\%form);
    $uri->as_string;
}

1;

__END__

=encoding utf8

=head1 NAME

Sledge::Authorizer::GoogleOAuth2

=head1 SYNOPSIS


    package My::Authorizer::GoogleOAuth2;
    
    use strict;
    use base qw(Sledge::Authorizer::GoogleOAuth2);
    
    __PACKAGE__->loginlink_template('/401oauth2.html');
    __PACKAGE__->client_id('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com');
    __PACKAGE__->client_secret('xxxxxxxxxxxxxxxxxxxxxxxx');
    __PACKAGE__->redirect_uri('http://xxxxxxxxxxxxxxxxxxxxxxxxxx/oauth2callback');
    
    sub authorize {
        my $self = shift;
        my $page = shift;
    
        return if $page->session->param('user');
    
        my ($email, $session) = $self->google_oauth2($page);
    
        my $user = My::Data::User->retrieve(email => $email);
        if ($user) {
            $page->session->param(user => $user);
            $page->redirect( $page->session->remove('__red') );
            return;
        } else {
            $page->session->param(__red => $ENV{PATH_INFO});
            $self->show_loginlink_page($page);
        }
    }

=head1 DESCRIPTION

Sledge::Authorizer::GoogleOAuth2 is....

=head1 AUTHOR

yseto

=head1 SEE ALSO

L<Sledge>

