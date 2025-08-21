package storage

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/ghostsecurity/vscan/internal/classifier"
	"github.com/ghostsecurity/vscan/internal/config"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Storage interface {
	StoreClassification(ctx context.Context, vulnID string, classification *classifier.Classification) error
	GetLastProcessedTimestamp(ctx context.Context) (string, error)
	UpdateLastProcessedTimestamp(ctx context.Context, timestamp string) error
	Close() error
}

type FirestoreStorage struct {
	client     *firestore.Client
	collection string
	projectID  string
}

type ProcessingState struct {
	LastProcessedTimestamp string    `firestore:"last_processed_timestamp"`
	UpdatedAt              time.Time `firestore:"updated_at"`
}

func NewFirestore(ctx context.Context, cfg *config.FirestoreConfig) (*FirestoreStorage, error) {
	var client *firestore.Client
	var err error

	// Try to use Application Default Credentials first
	client, err = firestore.NewClient(ctx, cfg.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("creating Firestore client: %w", err)
	}

	return &FirestoreStorage{
		client:     client,
		collection: cfg.Collection,
		projectID:  cfg.ProjectID,
	}, nil
}

func NewFirestoreWithCredentials(ctx context.Context, cfg *config.FirestoreConfig, credentialsPath string) (*FirestoreStorage, error) {
	client, err := firestore.NewClient(ctx, cfg.ProjectID, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return nil, fmt.Errorf("creating Firestore client with credentials: %w", err)
	}

	return &FirestoreStorage{
		client:     client,
		collection: cfg.Collection,
		projectID:  cfg.ProjectID,
	}, nil
}

func (fs *FirestoreStorage) StoreClassification(ctx context.Context, vulnID string, classification *classifier.Classification) error {
	_, err := fs.client.Collection(fs.collection).Doc(vulnID).Set(ctx, classification)
	if err != nil {
		return fmt.Errorf("storing classification for %s: %w", vulnID, err)
	}
	return nil
}

func (fs *FirestoreStorage) GetLastProcessedTimestamp(ctx context.Context) (string, error) {
	doc, err := fs.client.Collection("processing_state").Doc("vulnerability_scanner").Get(ctx)
	if err != nil {
		// If document doesn't exist, return empty string (start from beginning)
		if status.Code(err) == codes.NotFound {
			return "", nil
		}
		return "", fmt.Errorf("getting last processed timestamp: %w", err)
	}

	var state ProcessingState
	if err := doc.DataTo(&state); err != nil {
		return "", fmt.Errorf("parsing processing state: %w", err)
	}

	return state.LastProcessedTimestamp, nil
}

func (fs *FirestoreStorage) UpdateLastProcessedTimestamp(ctx context.Context, timestamp string) error {
	state := ProcessingState{
		LastProcessedTimestamp: timestamp,
		UpdatedAt:              time.Now(),
	}

	_, err := fs.client.Collection("processing_state").Doc("vulnerability_scanner").Set(ctx, state)
	if err != nil {
		return fmt.Errorf("updating last processed timestamp: %w", err)
	}

	return nil
}

func (fs *FirestoreStorage) Close() error {
	return fs.client.Close()
}

// BatchStoreClassifications stores multiple classifications in a transaction
func (fs *FirestoreStorage) BatchStoreClassifications(ctx context.Context, classifications map[string]*classifier.Classification) error {
	return fs.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		for vulnID, classification := range classifications {
			ref := fs.client.Collection(fs.collection).Doc(vulnID)
			if err := tx.Set(ref, classification); err != nil {
				return fmt.Errorf("setting classification in transaction: %w", err)
			}
		}
		return nil
	})
}

// GetClassification retrieves a stored classification
func (fs *FirestoreStorage) GetClassification(ctx context.Context, vulnID string) (*classifier.Classification, error) {
	doc, err := fs.client.Collection(fs.collection).Doc(vulnID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("getting classification for %s: %w", vulnID, err)
	}

	var classification classifier.Classification
	if err := doc.DataTo(&classification); err != nil {
		return nil, fmt.Errorf("parsing classification: %w", err)
	}

	return &classification, nil
}

// ClassificationExists checks if a classification already exists
func (fs *FirestoreStorage) ClassificationExists(ctx context.Context, vulnID string) (bool, error) {
	_, err := fs.client.Collection(fs.collection).Doc(vulnID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return false, nil
		}
		return false, fmt.Errorf("checking if classification exists: %w", err)
	}
	return true, nil
}
