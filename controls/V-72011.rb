control "xccdf_mil.disa.stig_rule_SV-86635r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that all local interactive users have a home directory assigned in the /etc/passwd file."
  desc  "
    Vulnerability Discussion: If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.
    
    Documentable: false
    
  "
  impact 0.5
  describe passwd do
    its("content") { should match(/^.*\:.*\:10.*\:10.*\:.*\:\/home\/.*\:\/bin\/bash.*$/) }
   end
 end

