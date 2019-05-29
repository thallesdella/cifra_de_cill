<?php

namespace Crypto;

/**
 * Cifra de Hill | Class implements Hill's cipher
 *
 * @author Thalles D. Koester <thallesdella@gmail.com>
 * @package Crypto
 */
class Hill
{
    /** @var string */
    private $msg;

    /** @var array */
    private $key;

    /** @var array */
    private $msg_ord;

    /** @var array */
    private $crypto_ord;

    /** @var array */
    private $crypto_ord_aux;

    /** @var string */
    private $crypto;

    /** @var array */
    private $alfabet = ['z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
        'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y'];

    /**
     * Método para configuração da chave de criptografia
     *
     * @param array $key Chave para criptografia
     * @return Hill
     */
    public function setKey(array $key): Hill
    {
        $this->key = ($this->isValid($key) ? $key : null);
        return $this;
    }

    /**
     * Método para configuração da mensage a ser criptografada
     *
     * @param string $msg Mensagem a ser criptografada
     * @return Hill
     */
    public function setMsg(string $msg): Hill
    {
        $this->msg = strtolower(preg_replace('/[^a-zA-Z]/', '', $msg));
        return $this;
    }

    /**
     * Método para obter resultado apos passar pelo algoritimo
     *
     * @return string
     */
    public function getResult(): string
    {
        return $this->crypto;
    }

    /**
     *  Método para selecionar modo de criptografia
     *
     * @return Hill
     */
    public function encrypt(): Hill
    {
        $this->crypto_ord = [];
        $this->msg_ord = $this->strToOrd($this->msg);

        foreach ($this->msg_ord as $key => $value) {
            $this->crypto_ord[] = $this->multiMatrix($this->key, $value);
        }

        $this->crypto = $this->ordToStr($this->crypto_ord);

        return $this;
    }

    /**
     * Método para selecionar modo de descriptografia
     *
     * Esse método serve como um wrapper para o método encrypt(). Esse o decrypt()
     * já ajusta os parametros para que a função encrypt() consiga realizar o caminho
     * reverso.
     *
     * @see Hill::inverseMatrixModular()
     * @see Hill::encrypt()
     * @return Hill
     */
    public function decrypt(): Hill
    {
        $this->key = $this->inverseMatrixModular($this->key);
        $this->encrypt();

        return $this;
    }

    /**
     * @param int $x
     * @return int
     */
    private function toBase(int $x): int
    {
        if ($x >= 0) {
            if ($x < count($this->alfabet)) {
                return $x;
            } else {
                return $x % count($this->alfabet);
            }
        }
        if ($x < 0) {
            return count($this->alfabet) + ($x % count($this->alfabet));
        }
        return 0;
    }

    /**
     * Método para verificar se matriz chave é válida para operação
     *
     * @param array $matrix
     * @return bool
     */
    private function isValid(array $matrix): bool
    {
        $det = $this->det($matrix);
        if (!$det) {
            return false;
        }
        if (abs($det - count($this->alfabet)) === 1) {
            return false;
        }
        return true;
    }

    /**
     * Método para calculo de determiante de matriz 2x2
     *
     * @param array $matrix
     * @return int
     */
    private function det(array $matrix): int
    {
        return $matrix[0][0] * $matrix[1][1] - ($matrix[0][1] * $matrix[1][0]);
    }

    /**
     * Método para converter os caracteres para ordinal
     *
     * @param string $msg
     * @return array
     */
    private function strToOrd(string $msg): array
    {
        if (strlen($msg) % 2 !== 0) {
            $msg = $this->strComplete($msg);
        }

        $ord = [];
        foreach (str_split($msg) as $key => $value) {
            $ord[] = array_search($value, $this->alfabet);
        }
        return $this->toColumMatrix($ord);
    }

    /**
     * Método para completar string
     *
     * @param string $msg
     * @return string
     */
    private function strComplete(string $msg): string
    {
        return $msg . substr($msg, -1);
    }

    /**
     * Método para transformar matriz em matriz coluna
     *
     * @param array $matrix
     * @return array
     */
    private function toColumMatrix(array $matrix): array
    {
        $ord = [];
        for ($i = 0; $i < count($matrix); $i += 2) {
            $ord[] = [[$matrix[$i]], [$matrix[$i + 1]]];
        }
        return $ord;
    }

    /**
     * Método para multiplicação de matriz
     *
     * @param array $matrix_a
     * @param array $matrix_b
     * @return array
     */
    private function multiMatrix(array $matrix_a, array $matrix_b): array
    {
        $array_result = [];
        for ($i = 0; $i < count($matrix_a); $i++) {
            for ($j = 0; $j < count($matrix_b[0]); $j++) {
                for ($k = 0; $k < count($matrix_b); $k++) {
                    @$array_result[$i][$j] = $array_result[$i][$j] + $matrix_a[$i][$k] * $matrix_b[$k][$j];
                }

            }
        }
        return $array_result;
    }

    /**
     * Método para converter os ordinal para caracter
     *
     * @param array $ord
     * @return string
     */
    private function ordToStr(array $ord): string
    {
        $str = '';
        $this->crypto_ord_aux = [];
        $this->toLineMatrix($ord);

        foreach ($this->crypto_ord_aux as $key => $value) {
            $str .= $this->alfabet[$this->toBase($value)];
        }

        return $str;
    }

    /**
     * Método para converter matriz em matriz linha
     *
     * @param array $matrix
     */
    private function toLineMatrix(array $matrix): void
    {
        foreach ($matrix as $key => $value) {
            if (is_array($value)) {
                $this->toLineMatrix($value);
            } else {
                $this->crypto_ord_aux[] = $value;
            }
        }
        return;
    }

    /**
     * Método para achar nverso modular de matrix 2x2
     *
     * @param array $matrix
     * @return array|bool
     */
    private function inverseMatrixModular(array $matrix)
    {
        $covMatrix = $this->covalentMatrix2($matrix);
        $inverse = gmp_intval(gmp_invert($this->det($matrix), count($this->alfabet)));

        if($inverse === false){
            return false;
        }

        $inverse_matrix = [];
        foreach ($covMatrix as $key => $valeus) {
            foreach ($valeus as $k => $v) {
                $inverse_matrix[$key][$k] = $this->toBase($covMatrix[$key][$k]*$inverse);
            }
        }

        return $inverse_matrix;
    }

    /**
     * Método para matriz de cofatores 2x2
     *
     * @param array $matrix
     * @return array
     */
    private function covalentMatrix2(array $matrix): array
    {
        $inv[0][0] = $matrix[1][1];
        $inv[0][1] = $matrix[0][1] * (-1);
        $inv[1][0] = $matrix[1][0] * (-1);
        $inv[1][1] = $matrix[0][0];
        return $inv;
    }
}
