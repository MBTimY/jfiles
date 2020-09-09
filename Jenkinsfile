pipeline {
    agent none 
    parameters {
		string(name: 'REPOURL', description: 'SCM repository url address')
		string(name: 'BRANCH', description: 'branch of repository')
    }

    stages {
        stage('prerequisite') {
        	agent any
	        steps {
	        	git url: params.REPOURL, branch: params.BRANCH
		        sh 'ls ./'
	        }
        }

        stage('compiler') {
            agent {
                docker {
                    image 'maven:3-alpine'
                    args '-v $HOME/.m2:/root/.m2'
                    }
            }
            steps {
		sh 'pwd'
		sh 'ls ./'
                sh 'mvn --version'
                sh 'mvn clean compile'
            }
        }

        stage('spotbugs') {
            agent {
                dockerfile {
                    filename 'Dockerfile'
                    dir 'spotbugs'
                    label 'spotbugs'
                    args '-v $HOME/.m2:/root/.m2'
                }
            }
            steps {
                sh '/analyze r ./'
            }
        }
    }
}
