# Runtime Verification of P4 Switches with Reinforcement Learning

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

In order to run the project make sure to have VirtualBox installed. If not already install go to [VirtualBox Website](https://www.virtualbox.org/wiki/Downloads) and follow the instructions to install it.
Also make sure to download the P4 Tutorial VM for VirtualBox from [here](https://drive.google.com/uc?id=1f22-DYlUV33DsR88_MeMb4s7-1NX_ams&export=download).
Clone the project by running:
```
git clone https://gitlab.inet.tu-berlin.de/apoorv/P4ML.git
```


### Installing

The following describes how to install necessary Python packages for running the project. The list of dependecies is provided with the requirements.txt file. In order to install the packages create a virtualenv and install the packages by running the following:

```
$ python3.6 -m venv PATH-WHERE-VENV-SHOULD-BE-PLACED/
$ PATH-TO-VENV/bin/pip3.6 install -r ./requirements.txt
```

## Running an example
For running the examples it is necessary to run the P4 tutorial VM and enable port forwarding for port 2222 to port 22 on the VM as described e.g. [here](https://nsrc.org/workshops/2014/btnog/raw-attachment/wiki/Track2Agenda/ex-virtualbox-portforward-ssh.htm). Now copy the contents of P4ML/P4/ folder to the VM by using e.g. SCP:

Hint: the password to the VM is: p4 
```
$ scp -P 2222 ./P4/* p4@127.0.0.1:~/tutorials/exercises/basic
```

Before proceeding, create necessary folders for the results of the P4RL Agent, e.g., for the default locations execute:
Note: if the folders are created in another directory than P4ML/ adjust the paths in net_agent.py accordingly.

```
$ cd PATH-TO-P4ML
$ mkdir results
$ mkdir model_save
$ mkdir figures
```

For execution of a training run of P4RL Agent, the switch placed in ~/tutorials/exercises/basic/ on the virtual box VM must be executed by running the following in a terminal of the VM.

```
$ cd ~/tutorials/exercises/basic
$ make run
```
This will create a Mininet environment with the topology described in P4ML/P4/topology.json using the switch defined by P4ML/P4/basic.p4.


In another terminal on the VM run:
Note: change the IP and Interface names to match your environments parameters.

```
$ cd ~/tutorials/exercises/basic
$ sudo ./receive_h1.py '192.168.102.224' 'enp0s3'
```

In another terminal on the VM run:
Note: change the IP and Interface names to match your environments parameters.

```
$ cd ~/tutorials/exercises/basic
$ sudo ./receive_h2.py '192.168.102.224' 'enp0s3'
``` 

In another terminal on the VM run:
Note: change the IP and Interface names to match your environments parameters.

```
$ cd ~/tutorials/exercises/basic
$ sudo ./receive_h3.py '192.168.102.224' 'enp0s3'
``` 

In another terminal on the VM run:

```
$ cd ~/tutorials/exercises/basic
$ ./mycontroller_l3switch.py
```


Before starting the net_env.py, the host IP has to be placed in variable Host_IP of the code in line 23. E.g.
```
Host_IP = '192.168.102.224'
```

Now the net_agent.py can be executed on the host machine. 

```
$ PATH-TO-VENV/bin/python3.6 ./net_agent.py
```

## Deployment


## Built With

* 
## Contributing


## Versioning

## Authors

*

## License

## Acknowledgments

*
