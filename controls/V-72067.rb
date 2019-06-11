
control "xccdf_mil.disa.stig_rule_SV-86691r4_rule" do
  title "The Red Hat Enterprise Linux operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards."
  desc  "
    Vulnerability Discussion: Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.
    
    Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000185-GPOS-00079, SRG-OS-000396-GPOS-00176, SRG-OS-000405-GPOS-00184, SRG-OS-000478-GPOS-00223
    
    Documentable: false
    
  "
  impact 1.0
  describe package('dracut') do
    it { should be_installed }
  end
  describe file("/etc/default/grub") do
    its("content") { should match('GRUB_CMDLINE_LINUX.*fips=1') }
  end
end
