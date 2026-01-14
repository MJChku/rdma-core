PROJECT_DIR := "/home/ubuntu/nex"
IB_LIB_PATH="/home/ubuntu/nex/src/sims/ib/rdma-core/build/lib"

NEX := /home/ubuntu/nex/nex
LD_PRELOAD="$(PROJECT_DIR)/src/accvm.so:$(PROJECT_DIR)/src/sims/gpu/nex_cuda.so"  

MPI_ENV := \
  LD_LIBRARY_PATH="$(IB_LIB_PATH):$(LD_LIBRARY_PATH)"

TARGET_MPI_ONE1=ib_write_bw -d nex0 -a  -n 2000 -p 20001

TARGET_MPI_ONE2=ib_write_bw -d nex0 -a  -n 2000 -p 20001 10.200.0.15

# TARGET_MPI_ONE1=ib_write_lat -d nex0 -s 8194300 -n 5 -p 20001

# TARGET_MPI_ONE2=ib_write_lat -d nex0  -s 8194300 -n 5 -p 20001 10.200.0.15


# TARGET_MPI_ONE1=ib_read_lat -d nex0 -a -n 5 -p 20001

# TARGET_MPI_ONE2=ib_read_lat -d nex0 -a -n 5 -p 20001 128.178.52.12

# TARGET_MPI_ONE1=ib_read_bw -d nex0 -a -n 2000 -p 20001 -N

# TARGET_MPI_ONE2=ib_read_bw -d nex0  -a -n 2000 -p 20001 10.1.2.1  -N


# TARGET_MPI_ONE1=./build/bin/ibv_rc_pingpong -d nex0 -p 20001 -n 1
# TARGET_MPI_ONE2=./build/bin/ibv_rc_pingpong -d nex0 -p 20001 10.1.2.1 -n 1 

COMMAND1 := '\
export NEX_ID=$$OMPI_COMM_WORLD_RANK; \
echo $$NEX_ID;\
$(NEX) $(TARGET_MPI_ONE1)'

COMMAND2 := '\
sleep 3; \
export NEX_ID=$$OMPI_COMM_WORLD_RANK; \
echo $$NEX_ID;\
$(NEX) $(TARGET_MPI_ONE2)'


COMMAND1 := '\
rm -f /dev/shm/*:*; \
export NEX_ID=0; \
echo $$NEX_ID;\
export NEX_NET_SHM=/nex_net_cluster_1;\
$(NEX) $(TARGET_MPI_ONE1)'

COMMAND2 := '\
rm -f /dev/shm/*:*; \
sleep 3; \
export NEX_ID=67;\
echo $$NEX_ID;\
export NEX_NET_SHM=/nex_net_cluster_2;\
$(NEX) $(TARGET_MPI_ONE2)'

# COMMAND1 := 'PORT=$$((12340 + $$OMPI_COMM_WORLD_RANK)); \
# export NEX_ID=$$OMPI_COMM_WORLD_RANK; \
#             echo "Rank $$OMPI_COMM_WORLD_RANK listening on port $$PORT"; \
#             exec gdbserver :$$PORT  $(TARGET_MPI_ONE1)'


# COMMAND2 := 'PORT=$$((12340 + $$OMPI_COMM_WORLD_RANK)); \
# export NEX_ID=$$OMPI_COMM_WORLD_RANK; \
#             echo "Rank $$OMPI_COMM_WORLD_RANK listening on port $$PORT"; \
#             exec gdbserver :$$PORT $(TARGET_MPI_ONE2)'

run:
	@echo "Running MPI OneDevicePerProcess test"
	@echo "Output will be written to mpi-one-rank-*.out files"
	@echo "rm shm files in /dev/shm/*:*"
	@rm -rf mpi-one-rank*
	@sudo rm -f /dev/shm/*:*
	@sudo rm -f /dev/shm/nex_qpcnt*
	$(MPI_ENV) \
	mpirun --hostfile /home/ubuntu/nex/config/app_hosts.txt \
	--bind-to none \
	--mca plm_rsh_no_tree_spawn 1 \
	--mca plm_rsh_num_concurrent 1 \
	--mca orte_startup_timeout 10 \
	--mca routed direct \
	--output-filename mpi-one-rank \
	-np 1 \
	-x LD_PRELOAD \
		-x LD_LIBRARY_PATH \
	   bash -lc $(COMMAND1) \
	: \
	-np 1 \
		-x LD_PRELOAD \
		-x LD_LIBRARY_PATH \
	   bash -lc $(COMMAND2) \