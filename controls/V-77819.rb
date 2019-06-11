control "xccdf_mil.disa.stig_rule_SV-92515r2_rule" do
  title "The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate users using multifactor authentication via a graphical user logon."
  desc  "
    Vulnerability Discussion: To assure accountability and prevent unauthenticated access, users must be identified and authenticated to prevent potential misuse and compromise of the system.

    Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.

    Satisfies: SRG-OS-000375-GPOS-00161,SRG-OS-000375-GPOS-00162
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("dconf").installed? }
  describe file("/etc/dconf/db/local.d/00-defaults") do
    it { should exist }
  end
  files = command("find /etc/dconf/db/local.d/.* type -f").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^.*\[org\/gnome\/login-screen\].*$/ } do 
    it { should_not be_empty }
    its("content") { should match(/^.*[\s]enable-smartcard-authentication=true.*[\s]$/) }
  end
end
