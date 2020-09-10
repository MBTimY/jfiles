pipeline {
    agent none 
    parameters {
		string(name: 'REPOURL', description: 'SCM repository url address')
		string(name: 'BRANCH', description: 'branch of repository')
    }

    stages {

        stage('compiler') {
            agent {
                dockerfile {
                    filenmae 'Dockerfile'
                    dir 'maven'
                    args '-v $HOME/.m2:$HOME/.m2'
                    addtionalBuildArgs '--build-arg USER_ID=$(id -u $USER) --build-arg GROUP_ID=$(id -g $USER)'
                    }
            }
            steps {
                git url: params.REPOURL, branch: params.BRANCH
                sh 'mvn --version'
                sh 'mvn clean compile'
            }
        }
    }
}