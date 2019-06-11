control "xccdf_mil.disa.stig_rule_SV-86937r2_rule" do
  title "SNMP community strings on the Red Hat Enterprise Linux operating system must be changed from the default."
  desc  "
    Vulnerability Discussion: Whether active or not, default Simple Network Management Protocol (SNMP) community strings must be changed to maintain security. If the service is running with the default authenticators, anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s). It is highly recommended that SNMP version 3 user authentication and message encryption be used in place of the version 2 community strings.
    
    Documentable: false
    
  "
  impact 1.0
  describe.one do
    describe package("net-snmp") do
      it { should_not be_installed }
    end
    describe file("/etc/snmp/snmpd.conf") do
      its("content") { should_not match(/^[\s]*(com2se|rocommunity|rwcommunity|createUser|authcommunity)[^#]*(public|private)/mi) }
    end
  end
end
