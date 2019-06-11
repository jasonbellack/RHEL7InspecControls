control "xccdf_mil.disa.stig_rule_SV-86943r2_rule" do
  title "The Red Hat Enterprise Linux operating system must not forward IPv6 source-routed packets."
  desc  "
    Vulnerability Discussion: Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    describe file('/proc/cmdline') do
      its('content') { should match /\bipv6\.disable=1\b/ }
    end
    describe file('/boot/grub2/grub.cfg') do
      its('content') { should match /^[^#]*\bipv6\.disable=1\b/ }
    end
    describe file('/boot/efi/EFI/redhat/grub.cfg') do
      its('content') { should match /^[^#]*\bipv6\.disable=1\b/ }
    end
    describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
      its('value') { should cmp 0 }
    end
  end
end
