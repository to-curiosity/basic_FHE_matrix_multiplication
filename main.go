package main

import (
	"fmt"
	//"reflect"
	"time"
	"math/rand"

	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/bfv"
	
)


func generateRandomMatrix(rows, cols int) [][]uint64 {
	// Initialize a seed for random number generation
	rand.Seed(time.Now().UnixNano())

	// Create a matrix with the specified dimensions
	matrix := make([][]uint64, rows)
	for i := 0; i < rows; i++ {
		matrix[i] = make([]uint64, cols)
		for j := 0; j < cols; j++ {
			// Generate random uint64 values
			matrix[i][j] = uint64(rand.Intn(100)) //1000
		}
	}

	return matrix
}

func MulMatrix(matrix1 [][]uint64, matrix2 [][]uint64) [][]uint64 {
    // Check if the matrices have compatible dimensions.
    if len(matrix1[0]) != len(matrix2) {
        fmt.Println("The matrices must have the same number of columns in order to be multiplied.")
        return nil
    }

    // Create a new matrix to store the result.
    result := make([][]uint64, len(matrix1))
    for i := range result {
        result[i] = make([]uint64, len(matrix2[0]))
    }

    // Perform the matrix multiplication.
    for i := range result {
        for j := range result[0] {
            for k := range matrix1[0] {
                result[i][j] += matrix1[i][k] * matrix2[k][j]
            }
        }
    }

    return result
}

func matrixToSlices(matrix [][]uint64) [][]uint64 {
    n := len(matrix)
    m := len(matrix[0])
    
    slices := make([][]uint64, n*m)
    
    for i := 0; i < n; i++ {
        for j := 0; j < m; j++ {
            slices[i*m+j] = []uint64{matrix[i][j]}
        }
    }
    
    return slices
}

func main() {

	/*
	Scenario: A client requests a third party to perform a multiplication operation between two matrices, referred to as matrixA and matrixB. 
	The third party is privy to the contents of matrixB. The client, however, wishes to keep matrixA and the resulting multiplication outcome 
	confidential from the third party. To achieve this, the client encrypts matrixA using their private key, and sends both matrixA and their 
	public key to the third party. Subsequently, the third party encrypts matrixB using the clients public key, proceeds with the calculation, 
	and then forwards the result to the client for decryption. This can be extended to both matrixA and matrixB being hidden from the third party.
	*/

	// Create and initialize MatrixA
	var start time.Time

    // Create and initialize MatrixA and MatrixB (row, col)
	/* 
	----------------EDIT HERE --------------------------
	*/
	matrixA := generateRandomMatrix(5,5)
	matrixB := generateRandomMatrix(5,5)
	 
	 // Print matrices then calculate matrix mult
	 fmt.Println("matrix A:", matrixA)
	 fmt.Println("matrix B:", matrixB)
	 start = time.Now()
	 matrix_mult_result := MulMatrix(matrixA, matrixB)
	 fmt.Println("A*B =:",matrix_mult_result)
	 fmt.Println()
	 //fmt.Printf("Homomorphic calc Done in %d ms\n", time.Since(start).Milliseconds())
	 duration := time.Since(start)
	 ms := duration.Seconds() * 1000
	 fmt.Printf("Regular Calc Done in %.6f ms\n", ms)
	 //fmt.Printf("Regular Calc Done in %d ms\n", time.Since(start).Milliseconds())


	 fmt.Println()
	
	//  homomorphic encryption section
	// BFV parameters (128 bit security) with plaintext modulus 65929217
	paramDef := bfv.PN13QP218 
	paramDef.T = 0x3ee0001  //0x3ee0001 hex --> 65929217 decimal

	params, err := bfv.NewParametersFromLiteral(paramDef)
	if err != nil {
		panic(err)
	}
	
	// setup scheme variables
	encoder := bfv.NewEncoder(params)
	kgen := bfv.NewKeyGenerator(params)
	firstSk, firstPk := kgen.GenKeyPair()
	decryptor := bfv.NewDecryptor(params, firstSk)
	encryptor_firstPk := bfv.NewEncryptor(params, firstPk)
	encryptor_firstSk := bfv.NewEncryptor(params, firstSk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{})

	fmt.Println("================================================================")
	fmt.Println("	  Homomorphic computations on batched integers")
	fmt.Println("================================================================")
	fmt.Println()
	fmt.Printf("Parameters : N=%d, T=%d, Q = %d bits, sigma = %f \n", 1<<params.LogN(), params.T(), params.LogQP(), params.Sigma())
	fmt.Println()
	

	// Get # of rows in matrix
	numRowsA := len(matrixA) 
	numRowsB := len(matrixB) 
	// Get # of columns in matrix
	numColsA := len(matrixA[0])
	numColsB := len(matrixB[0])

	size := 0
    if numColsA == numRowsB {
        size = numColsA
    } else {
        fmt.Println("Matrices don't match")
    }

	start = time.Now()

	// Flatten matrices array
	resultMatrixA := matrixToSlices(matrixA)
	//fmt.Println(resultMatrixA)
	resultMatrixB := matrixToSlices(matrixB)
	//fmt.Println(resultMatrixB)

	// Create plaintext, convert array to polynomails in R_t
	plain_matrixA := make([]*rlwe.Plaintext, numRowsA*numColsA) 
	for i := range plain_matrixA {
		plain_matrixA[i] = bfv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(resultMatrixA[i], plain_matrixA[i])
	}
	plain_matrixB := make([]*rlwe.Plaintext, numRowsB*numColsB) 
	for i := range plain_matrixB {
		plain_matrixB[i] = bfv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(resultMatrixB[i], plain_matrixB[i])
	}

	// Encrypt plaintext to create ciphertext
	ACiphertext := make([]*rlwe.Ciphertext, len(plain_matrixA))
	for i := range ACiphertext {
		ACiphertext[i] = encryptor_firstSk.EncryptNew(plain_matrixA[i])
	}
	BCiphertext := make([]*rlwe.Ciphertext, len(plain_matrixB))
	for i := range BCiphertext {
		BCiphertext[i] = encryptor_firstPk.EncryptNew(plain_matrixB[i])
	}

	// Define the result matrix (slice of slices)
	start = time.Now()
	resultCiphertextMatrix := make([]*rlwe.Ciphertext, numRowsA*numColsB)
	val0 := make([]*rlwe.Ciphertext, size)
	val1 := make([]*rlwe.Ciphertext, size)
	acum := 0
	for i := 0; i < numColsB; i++ {

		for j := 0; j < numRowsA*numColsA; j+=numColsA {
			//fmt.Println(" j: ",j)
			for k := 0; k< numRowsB; k++ {

				val0[k] = evaluator.MulNew(ACiphertext[j+k], BCiphertext[i+(k*numColsB)]) //3 items
				//fmt.Println("  k: ",k)
			}
			shallowCopy := val0[0].CopyNew()
			for ii := 0; ii < (len(val0) - 1); ii++ {
				//fmt.Println("ii: ",ii)
				val1[ii] = evaluator.AddNew(shallowCopy,val0[ii+1])
				shallowCopy = val1[ii]
			}
			
			resultCiphertextMatrix[acum] = shallowCopy
			//fmt.Println("		acum results: ", acum)
		acum += 1

		}
		
		}

	// Construct output matrix
	output_matrix := make([][]*rlwe.Ciphertext, numRowsA)
	for i := 0; i< numRowsA; i++ {
		output_matrix[i] = make([]*rlwe.Ciphertext, numColsB)
		for j := 0; j < numColsB; j ++ {
			output_matrix[i][j] = resultCiphertextMatrix[i+j*numRowsA]
		}
	}

	fmt.Printf("Homomorphic calc Done in %d ms\n", time.Since(start).Milliseconds())


	// Print out the output matrix 
	fmt.Print("[")
	for i := 0; i < numRowsA; i++ {
		fmt.Print("[")
		for j := 0; j < numColsB; j++ {
			decryptedResult := decryptor.DecryptNew(output_matrix[i][j])
			decodedResult := encoder.DecodeUintNew(decryptedResult)
			fmt.Printf("%d ", decodedResult[0])
			if j != numColsB-1 {
				fmt.Print(", ")
			}
		}
		fmt.Print("]")
		if i != numRowsA-1 {
			fmt.Print(", ")
		}
	}
	fmt.Println("]")

}