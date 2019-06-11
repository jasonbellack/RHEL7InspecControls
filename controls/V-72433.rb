control "xccdf_mil.disa.stig_rule_SV-87057r5_rule" do
  title "The Red Hat Enterprise Linux operating system must implement certificate status checking for PKI authentication."
  desc  "
    Vulnerability Discussion: Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

    Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.

    A privileged account is defined as an information system account with authorizations of a privileged user.

    Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

    This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

    Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000375-GPOS-00161, SRG-OS-000375-GPOS-00162
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    describe file("/etc/pam_pkcs11/pam_pkcs11.conf") do
      its("content") { should match(/^[\s]*cert_policy[\s]\=[\s].*[\s]ocsp_on.*$/) }
    end
    files = command("find /etc/pam_pkcs11/pam_pkcs11.conf -type f").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[\s]*cert_policy[\s]\=[\s].*[\s]ocsp_on.*$/ } do
      it { should_not be_empty }
    end
  end
end
