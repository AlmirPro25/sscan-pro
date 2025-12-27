pipeline {
    agent any
    
    environment {
        GEMINI_API_KEY = credentials('gemini-api-key')
        AEGIS_API_URL = 'http://localhost:8080'
        TARGET_URL = "${env.DEPLOY_URL ?: 'https://example.com'}"
    }
    
    stages {
        stage('Setup') {
            steps {
                script {
                    // Build CLI
                    sh '''
                        cd cli
                        go build -o aegis aegis.go
                        chmod +x aegis
                    '''
                }
            }
        }
        
        stage('Start Services') {
            parallel {
                stage('Backend') {
                    steps {
                        sh '''
                            cd backend
                            go build -o aegis-backend main.go
                            ./aegis-backend &
                            sleep 5
                        '''
                    }
                }
                stage('Worker') {
                    steps {
                        sh '''
                            cd backend/worker
                            npm install
                            node server.js &
                            sleep 5
                        '''
                    }
                }
            }
        }
        
        stage('Security Scan') {
            steps {
                sh '''
                    ./cli/aegis scan ${TARGET_URL} \
                        --fail-on high \
                        --output report.md \
                        --api ${AEGIS_API_URL}
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'report.md', fingerprint: true
            
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'report.md',
                reportName: 'AegisScan Security Report'
            ])
        }
        
        failure {
            emailext(
                subject: "Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Security vulnerabilities detected. Check the report at ${env.BUILD_URL}",
                to: "${env.SECURITY_TEAM_EMAIL}"
            )
        }
    }
}
