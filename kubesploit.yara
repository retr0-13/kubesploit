rule kubesploit
{
    meta:
		name = "kubesploit"
        description = "This is just an example"
        threat_level = 3

    strings:
        //$c = /github.com[a-zA-Z0-9\/]+/
		$s1 = "github.com/traefik/yaegigoto" ascii wide
		$s2 = "github.com/traefik/yaegi/stdlibgo" ascii wide
		$s3 = "github.com/traefik/yaegi/stdlib/unsafegob" ascii wide
		$s4 = "github.com/traefik/yaegi/stdlib/unsafe" ascii wide
		$s5 = "github.com/traefik/yaegi/stdlib/unrestrictedhexadecimal" ascii wide
		$s6 = "github.com/traefik/yaegi/stdlib/unrestricted" ascii wide
		$s7 = "github.com/traefik/yaegi/stdlib" ascii wide
		$s8 = "github.com/traefik/yaegi/interpgithub" ascii wide
		$s9 = "github.com/traefik/yaegi/interp" ascii wide
		$s10 = "github.com/traefik/yaegi" ascii wide
		$s11 = "github.com/satori/go" ascii wide
		$s12 = "github.com/refraction" ascii wide
		$s13 = "github.com/mattn/go" ascii wide
		$s14 = "github.com/marten" ascii wide
		$s15 = "github.com/lucas" ascii wide
		$s16 = "github.com/golang/protobuf/proto" ascii wide
		$s17 = "github.com/golang/protobuf" ascii wide
		$s18 = "github.com/francoispqt/gojay" ascii wide
		$s19 = "github.com/fatih/color" ascii wide
		$s20 = "github.com/cretz/gopaque/gopaque" ascii wide
		$s21 = "github.com/cretz/gopaque" ascii wide
		$s22 = "github.com/cheekybits/genny" ascii wide
		$s23 = "kubesploit/pkg/messages" ascii wide
		$s24 = "kubesploit/pkg/core" ascii wide
		$s25 = "kubesploit/pkg/agent" ascii wide
		$s26 = "github.com/Ne0nd0g/merlin" ascii wide
		$s27 = "github.com/Ne0nd0g/ja3transport" ascii wide

    condition:
	    all of ($s*)
}