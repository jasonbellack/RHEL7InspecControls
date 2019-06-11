control "xccdf_mil.disa.stig_rule_SV-86619r2_rule" do
  title "The Red Hat Enterprise Linux operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
  desc  "
    Vulnerability Discussion: Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.
    
    Documentable: false
    
  "
  impact 0.5
  describe command('grep \'^[\s]*UMASK.\+[0-9]*\' /etc/login.defs') do
    its('exit_status') { should eq 0 }
  end
  describe command('grep \'^[\s]*UMASK.\+[0-9]*\' /etc/login.defs').stdout.split.reject { |f| f == 'UMASK' }.first do
    it { should eq '077' }
  end
end
