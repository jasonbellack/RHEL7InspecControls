control "xccdf_mil.disa.stig_rule_SV-86593r2_rule" do
  title "The Red Hat Enterprise Linux operating system must not have the ypserv package installed."
  desc  "
    Vulnerability Discussion: Removing the \"ypserv\" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.
    
    Documentable: false
    
  "
  impact 1.0
  describe package("ypserv") do
    it { should_not be_installed }
  end
end
