control "xccdf_mil.disa.stig_rule_SV-86925r2_rule" do
  title "The Red Hat Enterprise Linux operating system must not have the Trivial File Transfer Protocol (TFTP) server package installed if not required for operational support."
  desc  "
    Vulnerability Discussion: If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.
    
    Documentable: false
    
  "
  impact 1.0
  describe package("tftp-server") do
    it { should_not be_installed }
  end
end

