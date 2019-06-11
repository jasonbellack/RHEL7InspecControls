control "xccdf_mil.disa.stig_rule_SV-86923r3_rule" do
  title "The Red Hat Enterprise Linux operating system must not have a File Transfer Protocol (FTP) server package installed unless needed."
  desc  "
    Vulnerability Discussion: The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.
    
    Documentable: false
    
  "
  impact 1.0
  describe package("vsftpd") do
    it { should_not be_installed }
  end
end
