## TODO: put license stuff

import random
import time
import numpy as np
from collections import deque
from keras.models import Sequential,load_model
from keras.layers import Dense
from keras.optimizers import Adam, Adadelta, SGD
from keras.initializers import RandomUniform
import struct
from net_env import networkEnv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

############### Paths for results, models, figures #################

FIGURES = "./figures/"
MODEL = "./model_save/"
RESULTS = "./results/"

############### Hyperparameters & Config #################

VERBOSE = False
counter=9
results_num = 0
GAMMA = 0.99
LEARNING_RATE = 0.00025
N_NEURONS = 128

MEMORY_SIZE = 1000000
BATCH_SIZE = 20

EXPLORATION_MAX = 1.0
EXPLORATION_MIN = 0.01
EXPLORATION_TEST = 0.02
EXPLORATION_STEPS = 50
EXPLORATION_DECAY = (EXPLORATION_MAX-EXPLORATION_MIN)/EXPLORATION_STEPS

pre_train_steps = 50
max_epLength = 2
num_episodes = 200
update_freq = 4
TARGET_NETWORK_UPDATE_FREQUENCY = 12

q_value_save = []
OPTIMIZER = SGD(lr=LEARNING_RATE)
n_input = 5 # Data input in our case is 20 Bytes converted to 5 4-Byte floats, hence 5 is the input size
n_actions = 20 # number of actions in the RL env
jList = []
rList = []
cumulative_reward = []


def reset_values():
    q_value_save.clear()
    jList.clear()
    rList.clear()
    cumulative_reward.clear()

class DDQNSolver:
    def __init__(self, load_model=False):
        self.steps = 0
        self.load_model = load_model
        self.exploration_rate = EXPLORATION_MAX
        initializer = RandomUniform(minval=0, maxval=0.1, seed=None)
        self.action_distr = np.zeros(n_actions)
        self.predicted_a = np.zeros(n_actions)
        self.action_space = n_actions
        self.memory = deque(maxlen=MEMORY_SIZE)
        if not self.load_model:
            self.ddqn = Sequential()
            self.ddqn.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', input_dim=n_input, activation="tanh"))
            self.ddqn.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', activation="tanh"))
            self.ddqn.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', activation="tanh"))
            self.ddqn.add(Dense(self.action_space, activation="softmax"))
            self.ddqn.compile(loss="categorical_crossentropy", optimizer=OPTIMIZER)

            self.ddqn_target = Sequential()
            self.ddqn_target.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', input_dim=n_input, activation="tanh"))
            self.ddqn_target.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', activation="tanh"))
            self.ddqn_target.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', activation="tanh"))
            self.ddqn_target.add(Dense(self.action_space, activation="softmax"))
            self.ddqn_target.compile(loss="categorical_crossentropy", optimizer=OPTIMIZER)
        else:
            self.load()

    def __del__(self):
        print("DDQN Solver deleted")

    def load(self):
        self.ddqn = load_model(MODEL + "DDQN_online_agent_%s.h5" % counter)
        self.ddqn_target = load_model(MODEL + "DDQN_target_agent_%s.h5" % counter)
        return

    def save_model(self):
        self.ddqn.save(MODEL + "DDQN_online_agent_%s.h5" % counter)
        self.ddqn_target.save(MODEL + "DDQN_target_agent_%s.h5" % counter)
        return

    def remember(self, state, action, reward, next_state, done):
        self.memory.append((state, action, reward, next_state, done))
        if len(self.memory) > MEMORY_SIZE:
            self.memory.pop(0)

    def act_random(self):
        return random.randrange(self.action_space)
    def act_load(self, state):
        state = state.reshape((1, n_input))
        q_values = self.ddqn.predict(state)
        q_value_save.append(q_values)
        self.predicted_a[np.argmax(q_values[0])] = int(self.predicted_a[np.argmax(q_values[0])] + 1)
        return np.argmax(q_values[0])

    def act(self, state):
        if np.random.rand() < self.exploration_rate:
            return random.randrange(self.action_space)
        state = state.reshape((1, n_input))
        q_values = self.ddqn.predict(state)
        q_value_save.append(q_values)
        self.predicted_a[np.argmax(q_values[0])] = int(self.predicted_a[np.argmax(q_values[0])] + 1)
        return np.argmax(q_values[0])

    def _reset_target_network(self):
        self.ddqn_target.set_weights(self.ddqn.get_weights())

    def experience_replay(self):
        self.steps += 1
        if len(self.memory) < BATCH_SIZE or self.steps < pre_train_steps:
            return
        buffer = sorted(self.memory, key=lambda replay: replay[2], reverse=True)

        p = np.array([0.85 ** i for i in range(len(buffer))])
        sum_p = sum(p)

        for i in range(0, len(p)):
            p[i] = p[i] / sum_p

        sample_ids = np.random.choice(np.arange(len(buffer)), size=BATCH_SIZE, p=p)
        batch = [buffer[id] for id in sample_ids]

        if self.steps % update_freq == 0:
            for state, action, reward, state_next, terminal in batch:
                q_update = reward
                if not terminal:
                    state_next = state_next.reshape((1,n_input))
                    q_update = (reward + GAMMA * np.amax(self.ddqn_target.predict(state_next)[0]))

                state = state.reshape((1,n_input))
                q_values = self.ddqn.predict(state)
                q_values[0][action] = q_update

                self.ddqn.fit(state, q_values, verbose=0)

        if self.steps > pre_train_steps:
            self.exploration_rate -= EXPLORATION_DECAY

        self.exploration_rate = max(EXPLORATION_MIN, self.exploration_rate)

        if self.steps % TARGET_NETWORK_UPDATE_FREQUENCY == 0:
            self._reset_target_network()

def processState(states):
    if VERBOSE:
        print("State in bytes: ", bytes(states))
    if len(states) == 19:
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(states)))
    elif len(states) == 18:
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(states)))
    elif len(states) == 17:
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(states)))
    elif len(states) == 16:
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(states)))
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(
            bytes(states)))

    if VERBOSE:
        print("State in bytes: ",  bytes(states))

    byte_to_float = []
    i = 0
    for i in [0,4,8,12,16]:
        byte_to_float.append(struct.unpack('f', bytearray(states)[i:i+4]))
    return np.reshape(byte_to_float, [n_input])

def run(run_num):
    with networkEnv(4, verbose=VERBOSE) as env:
        env.reward_system.run = run_num
        # change load_model if trained model exists already
        ddqn_solver = DDQNSolver(load_model=False)
        start = time.time()
        run = 0
        first_reward = False
        first_reward_seen = 0
        first_bug_time = -1
        if not ddqn_solver.load_model:
            for i in range(num_episodes):
                run += 1
                state = env.reset()
                state = processState(state)
                step = 0
                rAll = 0
                while step < max_epLength:
                    d = False
                    step += 1
                    action = ddqn_solver.act(state)

                    # dqn_solver.action_distr is only for keeping track of how often each
                    # of the available actions were chosen in the course of training
                    ddqn_solver.action_distr[action] = int(ddqn_solver.action_distr[action] + 1)
                    state_next, reward = env.execute(action)
                    if step == max_epLength:
                        terminal = True
                        reward = env.check_reward()
                    else:
                        terminal = False

                    if reward is not None:
                        d = True
                    else:
                        reward = 0
             
                    state_next = processState(state_next)
                  
                    if reward==1 and first_reward==False:
                        first_reward = True
                        first_reward_seen = run
                        first_bug_time = time.time() - start
                    ddqn_solver.remember(state, action, reward, state_next, terminal)
                    state = state_next
                    ddqn_solver.experience_replay()
                    if terminal or d:
                        if run % 100 == 0:

                            print ("Run: " + str(run) + ", exploration: " + str(ddqn_solver.exploration_rate) + ", score: " + str(step))
                            print("Reward: ", reward)
                        rAll += reward
                        break

                rList.append(rAll)
                jList.append(step)
                cumulative_reward.append(sum(rList))
            ddqn_solver.save_model()
        else:
            for i in range(num_episodes):
                run += 1
                state = env.reset()
                state = processState(state)
                step = 0
                rAll = 0
                while step < max_epLength:
                    d = False
                    step += 1
                    action = ddqn_solver.act_load(state)
                    ddqn_solver.action_distr[action] = int(ddqn_solver.action_distr[action] + 1)
                    state_next, reward = env.execute(action)
                    if step == max_epLength:
                        terminal = True
                        reward = env.check_reward()
                    else:
                        terminal = False
                    if reward is not None:
                        d = True
                    else:
                        reward = 0
                    if reward==1 and not first_reward:
                        first_reward = True
                        first_reward_seen = run
                        first_bug_time = time.time() - start
                        rAll += reward
                        break
                rList.append(rAll)
                jList.append(step)
                cumulative_reward.append(sum(rList))
                if first_reward:
                    break
        end = time.time()
        execution_time = end - start
        t = np.arange(0.0, run, 1)
        s = cumulative_reward
        file=open(RESULTS + "DDQN_prio_replay_results_%s.txt" % results_num, "a")
        file.write("Action distribution: %s \n" % list(map(int, ddqn_solver.action_distr)))
        file.write("Number of actions per episode: %s \n" % sum(jList))
        file.write("Predicted a: %s \n" % list(map(int, ddqn_solver.predicted_a)))
        file.write("Learning Rate used: %s \n" % LEARNING_RATE)
        file.write("Number of Neurons: %s \n" % N_NEURONS)
        file.write("Optimizer used: %s \n" % OPTIMIZER)
        file.write("Max number of steps: %s \n" % max_epLength)
        file.write("Cumulative Reward: %s \n" % max(cumulative_reward))
        file.write("Cumulative Reward for plotting: %s \n" % list(cumulative_reward))
        file.write("X for plotting cumulative reward: %s \n" % list(t))
        file.write("start time: %s \n" % start)
        file.write("end time: %s \n" % end)
        file.write("execution time: %s \n" % execution_time)
        file.write("first reward seen after %s runs. \n" % first_reward_seen)
        file.write("first reward seen after %s seconds. \n" % first_bug_time)
        file.write("\n")
        file.close()

        print("Action distribution: ", list(map(int, ddqn_solver.action_distr)))
        print("Number of actions per episode: ", sum(jList))
        print("Predicted a: ", list(map(int, ddqn_solver.predicted_a)))
        print("Cumulative Reward: ", max(cumulative_reward))
        print("Learning Rate used: ", LEARNING_RATE)
        print("Number of Neurons: ", N_NEURONS)
        print("Optimizer used: ", OPTIMIZER )
        print("Max number of steps: ", max_epLength)
        if not ddqn_solver.load_model:
            fig, ax = plt.subplots()

            ax.plot(t, s)
            ax.set(xlabel='Number of Steps', ylabel='Cumulative Reward')
            fig.savefig(FIGURES + "DDQN_cumulative_reward_%s.png" % counter)
            #plt.show()
            fig.clear()

        env.clean_up()
        time.sleep(1)
        del env

# Full random baseline
def run_random(run_num):
    with networkEnv(4, verbose=VERBOSE) as env:
        start = time.time()
        env.reward_system.run = run_num
        run = 0
        first_reward = False
        first_reward_seen = 0
        first_bug_time = -1
        for i in range(num_episodes):
            run += 1
            rAll = 0
            reward = env.check_random_reward()
            if reward is not None:
                d = True
            else:
                reward = 0

            if reward == 1 and first_reward == False:
                first_reward = True
                first_reward_seen = run
                first_bug_time = time.time() - start

            rAll += reward
            rList.append(rAll)
            cumulative_reward.append(sum(rList))

        t = np.arange(0.0, num_episodes, 1)
        s = cumulative_reward
        end = time.time()
        file = open("full_random_results_%s.txt" % results_num, "a")

        execution_time = end - start

        file.write("Cumulative Reward: %s \n" % max(cumulative_reward))
        file.write("Cumulative Reward for plotting: %s \n" % list(cumulative_reward))
        file.write("X for plotting cumulative reward: %s \n" % list(t))
        file.write("start time: %s \n" % start)
        file.write("end time: %s \n" % end)
        file.write("execution time: %s \n" % execution_time)
        file.write("first reward seen after %s runs. \n" % first_reward_seen)
        file.write("first reward seen after %s seconds. \n" % first_bug_time)
        file.write("\n")
        file.close()

        fig, ax = plt.subplots()

        ax.plot(t, s)
        ax.set(xlabel='Number of Steps', ylabel='Cumulative Reward')
        fig.savefig(RESULTS + "Random_cumulative_reward_%s.png" % counter)

        fig.clear()

        env.clean_up()
        time.sleep(1)
        del env

    return


if __name__ == "__main__":
    results_num = 3
    
    #DDQN
    file = open(RESULTS + "DDQN_prio_replay_results_%s.txt" % results_num, "a")

    #Random Baseline
    #file = open(RESULTS + "full_random_results_%s.txt" % results_num, "a")
    #file.write("Random run: \n")

    file.write("Parameters used: \n")
    file.write("Gamma: %s \n" % GAMMA)
    file.write("Learning Rate: %s \n" % LEARNING_RATE)
    file.write("Number of Neurons: %s \n" % N_NEURONS)
    file.write("Memory size: %s \n" % MEMORY_SIZE)
    file.write("Batch Size: %s \n" % BATCH_SIZE)
    file.write("Exploration Max: %s \n" % EXPLORATION_MAX)
    file.write("Exploration Min: %s \n" % EXPLORATION_MIN)
    file.write("Exploration Test: %s \n" % EXPLORATION_TEST)
    file.write("Exploration Steps: %s \n" % EXPLORATION_STEPS)
    file.write("Exploration Decay: %s \n" % EXPLORATION_DECAY)
    file.write("Pre Train Steps: %s \n" % pre_train_steps)
    file.write("Max EP Length: %s \n" % max_epLength)
    file.write("Number of Episodes: %s \n" % num_episodes)
    file.write("Update Frequency: %s \n" % update_freq)
    file.write("Target Network Update Frequency: %s \n" % TARGET_NETWORK_UPDATE_FREQUENCY)
    file.write("\n")
    file.write("\n")
    file.write("\n")
    file.close()

    run(run_num=3)
    #run_number = 4
    # for i in range(2):
    #      #time.sleep(2)
    #      reset_values()
    #      run_random(run_num=run_number)
    #      #run(run_num=run_number)
    #      counter+=1
    #      run_number+=1
    #      gc.collect()

