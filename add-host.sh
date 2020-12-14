sudo ip netns add d
sudo ip link add dserver type veth peer name dclient
sudo ip link set dserver netns d
sudo ifconfig dclient 172.14.253.65/8 up
sudo ip netns exec d ifconfig dserver 172.17.1.22/8 up
sudo ip netns exec d ifconfig lo up
