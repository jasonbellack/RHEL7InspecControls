control "xccdf_mil.disa.stig_rule_SV-86591r2_rule" do
  title "The Red Hat Enterprise Linux operating system must not have the rsh-server package installed."
  desc  "
    Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.
    
    Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
    
    The rsh-server service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication.
    
    If a privileged user were to log on using this service, the privileged user password could be compromised.
    
    Documentable: false
    
  "
  impact 1.0
  describe package("rsh-server") do
    it { should_not be_installed }
  end
end
