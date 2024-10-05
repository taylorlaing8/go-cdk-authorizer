package main

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var rootDirectory = "src"

func main() {
	start := time.Now()

	fmt.Println("Finding Go Lambda function code directories...")

	dirs, err := getDirectoriesContainingMainGoFiles(fmt.Sprintf("./%v", rootDirectory))

	if err != nil {
		fmt.Printf("Failed to get directories containing main.go files: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%d Lambda entrypoints found...\n", len(dirs))

	for i := 0; i < len(dirs); i++ {
		fmt.Printf("Tidying Lambda %d of %d...\n", i+1, len(dirs))
		err = runModTidy(dirs[i])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Building Lambda %d of %d...\n", i+1, len(dirs))
		err = buildMainGoFile(dirs[i])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Zipping Lambda %d of %d...\n", i+1, len(dirs))
		err = zipBootstrapFile(dirs[i])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Moving Bootstrap File %d of %d to Dist Folder...\n", i+1, len(dirs))
		err = moveBootstrapFileToDist(dirs[i])
	}

	fmt.Printf("Built %d Lambda functions in %v\n", len(dirs), time.Now().Sub(start))
}

func getDirectoriesContainingMainGoFiles(srcPath string) (paths []string, err error) {
	filepath.Walk(srcPath, func(currentPath string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			// Continue.
			return nil
		}

		d, f := path.Split(currentPath)

		if f == "main.go" {
			paths = append(paths, d)
		}

		return nil
	})

	if err != nil {
		err = fmt.Errorf("failed to walk directory: %w", err)
		return
	}

	return
}

func runModTidy(path string) error {
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = path
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error running command: %w", err)
	}

	if exitCode := cmd.ProcessState.ExitCode(); exitCode != 0 {
		return fmt.Errorf("non-zero exit code: %v", exitCode)
	}

	return nil
}

func buildMainGoFile(path string) error {
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", "bootstrap")
	cmd.Dir = path
	cmd.Env = append(os.Environ(),
		"GOOS=linux",
		"GOARCH=arm64",
		"CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error running command: %w", err)
	}

	if exitCode := cmd.ProcessState.ExitCode(); exitCode != 0 {
		return fmt.Errorf("non-zero exit code: %v", exitCode)
	}

	return nil
}

func zipBootstrapFile(path string) error {
	sourcePath := fmt.Sprintf("./%v", path)

	bootstrap, err := os.Create(sourcePath + "bootstrap.zip")
	if err != nil {
		return fmt.Errorf("error creating zip file: %w", err)
	}
	defer bootstrap.Close()

	zipWriter := zip.NewWriter(bootstrap)
	defer zipWriter.Close()

	binary, err := os.Open(sourcePath + "bootstrap")
	if err != nil {
		return fmt.Errorf("error opening bootstrap binary file: %w", err)
	}
	defer binary.Close()

	binaryStat, err := binary.Stat()
	if err != nil {
		return fmt.Errorf("error reading stats of binary file: %w", err)
	}

	binaryHeader, err := zip.FileInfoHeader(binaryStat)
	if err != nil {
		return fmt.Errorf("error creating zip header from binary stats: %w", err)
	}

	binaryHeader.Name = "bootstrap"
	binaryHeader.Method = zip.Deflate

	binaryWriter, err := zipWriter.CreateHeader(binaryHeader)
	if err != nil {
		return fmt.Errorf("error creating binary writer from header: %w", err)
	}

	_, err = io.Copy(binaryWriter, binary)

	return nil
}

func moveBootstrapFileToDist(path string) error {
	destinationBase := "./dist"

	err := os.Mkdir(destinationBase, 0777)
	if err != nil && !os.IsExist(err) {
		fmt.Printf("error creating destination base directory: %v", err.Error())
	}

	fileName := "bootstrap"
	sourcePath := fmt.Sprintf("./%v%v.zip", path, fileName)
	destinationPath := destinationBase + strings.Replace(strings.Replace(path, "/lambda", "", 1), rootDirectory, "", 1)

	inputFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("error opening source file: %w", err)
	}
	defer inputFile.Close()

	err = os.Mkdir(destinationPath, 0777)
	if err != nil && !os.IsExist(err) {
		fmt.Printf("error creating directory: %v", err.Error())
	}

	outputFile, err := os.Create(fmt.Sprintf("%v%v.zip", destinationPath, fileName))
	if err != nil {
		return fmt.Errorf("error opening destination file: %w", err)
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, inputFile)
	if err != nil {
		return fmt.Errorf("error copying to destination from source: %w", err)
	}

	inputFile.Close()

	err = os.Remove(fmt.Sprintf("./%v%v", path, fileName))
	if err != nil {
		return fmt.Errorf("error removing source bootstrap file: %w", err)
	}

	err = os.Remove(sourcePath)
	if err != nil {
		return fmt.Errorf("error removing source bootstrap.zip file: %w", err)
	}

	return nil
}
