control "xccdf_mil.disa.stig_rule_SV-86603r2_rule" do
  title "The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization."
  desc  "
    Vulnerability Discussion: Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.
    
    Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.
    
    Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.
    
    Documentable: false
    
  "
  impact 1.0
  describe file("/etc/yum.conf") do
    its("content") { should match(/^\s*localpkg_gpgcheck\s*=\s*(\S+)\s*$/) }
  end
  file("/etc/yum.conf").content.to_s.scan(/^\s*localpkg_gpgcheck\s*=\s*(\S+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(1|True|yes)$/) }
    end
  end
end

