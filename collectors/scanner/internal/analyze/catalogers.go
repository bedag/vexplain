package analyze

// The package types and catalogers that more than one place names.
const (
	typeAPK              = "apk"
	typeDeb              = "deb"
	typeDotnet           = "dotnet"
	typeBinary           = "binary"
	javascriptCataloger  = "javascript-package-cataloger"
	javaArchiveCataloger = "java-archive-cataloger"
	dotnetDepsCataloger  = "dotnet-deps-binary-cataloger"
)

// catalogerTypes holds the package types of each image cataloger of Syft v1.55.0, as its source gives them: the
// strings that SBOMPackage.Type and a finding's package type carry. A cataloger may be listed with more types than it
// emits, never fewer, since a type that it lacks lets a guard pass the findings that the failure may have hidden.
// A cataloger whose types are open-ended or unchecked is left out, such as the binary classifier, which takes the type
// of a package from the purl of what it finds.
var catalogerTypes = map[string][]string{
	"alpm-db-cataloger":                  {"alpm"},
	"apk-db-cataloger":                   {typeAPK},
	"dpkg-db-cataloger":                  {typeDeb},
	"portage-cataloger":                  {"portage"},
	"rpm-db-cataloger":                   {"rpm"},
	"conan-info-cataloger":               {"conan"},
	javascriptCataloger:                  {"npm"},
	"php-composer-installed-cataloger":   {"php-composer"},
	"php-pear-serialized-cataloger":      {"php-pear"},
	"r-package-cataloger":                {"R-package"},
	"ruby-installed-gemspec-cataloger":   {"gem"},
	"cargo-auditable-binary-cataloger":   {"rust-crate"},
	dotnetDepsCataloger:                  {typeDotnet},
	"dotnet-packages-lock-cataloger":     {typeDotnet},
	"python-installed-package-cataloger": {"python"},
	"go-module-binary-cataloger":         {"go-module"},
	javaArchiveCataloger:                 {"java-archive", "jenkins-plugin"},
	"nix-cataloger":                      {"nix"},
	"lua-rock-cataloger":                 {"lua-rocks"},
	"perl-cpan-installed-cataloger":      {"cpan"},
	"elf-binary-package-cataloger":       {"alpm", typeAPK, typeBinary, typeDeb, "rpm"},
	"pe-binary-package-cataloger":        {typeBinary},
	"java-jvm-cataloger":                 {typeBinary},
	"linux-kernel-cataloger":             {"linux-kernel", "linux-kernel-module"},
	"bitnami-cataloger":                  {"bitnami"},
	"wordpress-plugins-cataloger":        {"wordpress-plugin"},
	"homebrew-cataloger":                 {"homebrew"},
	"apple-app-bundle-cataloger":         {"apple-app-bundle"},
	"snap-cataloger":                     {typeDeb},
	"gguf-cataloger":                     {"model"},
	"safetensors-cataloger":              {"model"},
}

// packageTypesOf returns the package types that a Syft cataloger catalogs, or none for a cataloger that the table
// doesn't know, which a guard reads as: any type.
func packageTypesOf(cataloger string) []string {
	return catalogerTypes[cataloger]
}
