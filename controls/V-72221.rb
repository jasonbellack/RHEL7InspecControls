control "xccdf_mil.disa.stig_rule_SV-86845r3_rule" do
  title "The Red Hat Enterprise Linux operating system must use a FIPS 140-2 approved cryptographic algorithm for SSH communications."
  desc  "
    Vulnerability Discussion: Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.
    
    Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.
    
    FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.
    
    Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000120-GPOS-00061, SRG-OS-000125-GPOS-00065, SRG-OS-000250-GPOS-00093, SRG-OS-000393-GPOS-00173
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("Ciphers") { should_not be_nil }
    its("Ciphers") { should match(/^"?((aes128-ctr|aes192-ctr|aes256-ctr),?)+"?[\s]*(?:|(?:#.*))?$/) }
  end
end
