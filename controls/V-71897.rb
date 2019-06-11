control "xccdf_mil.disa.stig_rule_SV-86521r2_rule" do
  title "The Red Hat Enterprise Linux operating system must have the screen package installed."
  desc  "
    Vulnerability Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
    
    The screen package allows for a session lock to be implemented and configured.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("dconf").installed? }
  describe package("screen") do
    it { should be_installed }
  end
end
