import random

class DH():  # Diffie-Hellman set-up
    def __init__(self, length=512):
        self.p = self.generate_prime(length)
        self.alpha = random.randrange(2, self.p-2)

    def is_prime(self, n):
        """
        Miller-Rabin primality test.

        A return value of False means n is certainly not prime. A return value of
        True means n is very likely a prime.
        """
        if n != int(n):
            return False
        n = int(n)
        # Miller-Rabin test for prime
        if n == 0 or n == 1 or n == 4 or n == 6 or n == 8 or n == 9:
            return False

        if n == 2 or n == 3 or n == 5 or n == 7:
            return True
        s = 0
        d = n - 1
        while d % 2 == 0:
            d >>= 1
            s += 1
        assert (2 ** s * d == n - 1)

        def trial_composite(a):
            if pow(a, d, n) == 1:
                return False
            for i in range(s):
                if pow(a, 2 ** i * d, n) == n - 1:
                    return False
            return True

        for i in range(5):  # number of trials
            a = random.randrange(2, n)
            if trial_composite(a):
                return False
        return True

    def generate_prime(self, length): # length of prime in bits
        p = 4
        while not self.is_prime(p):
            p = random.getrandbits(length)
            # apply a mask to set MSB and LSB to 1
            p |= (1 << length - 1) | 1
        return p


class Key_exchange:
    def __init__(self, p, alpha):
        self.p = p
        self.alpha = alpha
        self.a = random.randrange(2, p-2)

    def pub_key(self):
        return pow(self.alpha, self.a, self.p)

    def produce_key(self, B):
        return pow(B, self.a, self.p)


def test():
    dh = DH()  # Diffie-Hellman set up
    p = dh.p
    alpha = dh.alpha
    Alice = Key_exchange(p, alpha)
    A = Alice.pub_key()
    Bob = Key_exchange(p, alpha)
    B = Bob.pub_key()
    print(Alice.produce_key(B) == Bob.produce_key(A))


if __name__ == '__main__':
    test()
