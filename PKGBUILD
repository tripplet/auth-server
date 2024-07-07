pkgname=auth-server
pkgver=1.3.9
pkgrel=1
pkgdesc='Service for authenticating requests from nginx (ngx_http_auth_request_module).'
url="https://github.com/tripplet/auth-server"
arch=('x86_64' 'armv7h' 'aarch64')
depends=()
makedepends=(rust)

build() {
  cd $srcdir/..
  cargo build --release --locked
}

package()
{
  cd $pkgdir/../..
  install -Dm 755 "target/release/auth-server" -t "${pkgdir}/usr/bin"
  install -Dm 644 "auth-server.service" -t "${pkgdir}/usr/lib/systemd/system"
}

