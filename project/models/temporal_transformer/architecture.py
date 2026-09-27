import torch
import torch.nn as nn
import math

class FocalLoss(nn.Module):
    def __init__(self, alpha=None, gamma=2):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.ce = nn.CrossEntropyLoss(reduction='none')
        
    def forward(self, inputs, targets):
        ce_loss = self.ce(inputs, targets)
        pt = torch.exp(-ce_loss)
        
        if self.alpha is not None:
            if self.alpha.device != inputs.device:
                self.alpha = self.alpha.to(inputs.device)
            at = self.alpha.gather(0, targets.view(-1)).view(targets.shape)
        else:
            at = 1.0
            
        focal_loss = at * (1 - pt) ** self.gamma * ce_loss
        return focal_loss.mean()

class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=5000):
        super(PositionalEncoding, self).__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0) # (1, max_len, d_model)
        self.register_buffer('pe', pe)

    def forward(self, x):
        # x shape: (batch_size, seq_len, d_model)
        x = x + self.pe[:, :x.size(1), :]
        return x

class ClassificationHead(nn.Module):
    def __init__(self, embedding_dim, num_classes, hidden_dim=64):
        super(ClassificationHead, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(embedding_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, num_classes)
        )
        
    def forward(self, state_repr):
        return self.net(state_repr)

class ForecastingHead(nn.Module):
    def __init__(self, embedding_dim, num_classes, horizons=['future_5s', 'future_10s', 'future_15s', 'future_30s', 'future_60s'], hidden_dim=64):
        super(ForecastingHead, self).__init__()
        self.horizons = horizons
        
        self.horizon_networks = nn.ModuleDict({
            h: nn.Sequential(
                nn.Linear(embedding_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(hidden_dim, num_classes)
            ) for h in horizons
        })

    def forward(self, state_repr):
        predictions = {}
        for h in self.horizons:
            predictions[h] = self.horizon_networks[h](state_repr)
        return predictions

class FutureStatePredictionHead(nn.Module):
    def __init__(self, embedding_dim, input_dim, hidden_dim=64):
        super(FutureStatePredictionHead, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(embedding_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, input_dim)
        )
        
    def forward(self, state_repr):
        return self.net(state_repr)

class TemporalTransformer(nn.Module):
    def __init__(self, input_dim, num_classes, embedding_dim=128, num_layers=4, num_heads=4, ff_dim=256, dropout=0.1, seq_len=60, horizons=['future_5s', 'future_10s', 'future_15s', 'future_30s', 'future_60s']):
        super(TemporalTransformer, self).__init__()
        
        self.input_projection = nn.Linear(input_dim, embedding_dim)
        self.pos_encoder = PositionalEncoding(embedding_dim, max_len=seq_len)
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embedding_dim,
            nhead=num_heads,
            dim_feedforward=ff_dim,
            dropout=dropout,
            batch_first=True
        )
        
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.layer_norm = nn.LayerNorm(embedding_dim)
        
        # Classification and Forecasting Heads
        self.classification_head = ClassificationHead(embedding_dim, num_classes)
        self.forecasting_head = ForecastingHead(embedding_dim, num_classes, horizons=horizons)
        self.future_state_head = FutureStatePredictionHead(embedding_dim, input_dim)
        
    def generate_square_subsequent_mask(self, sz, device):
        mask = (torch.triu(torch.ones((sz, sz), device=device)) == 1).transpose(0, 1)
        mask = mask.float().masked_fill(mask == 0, float('-inf')).masked_fill(mask == 1, float(0.0))
        return mask
        
    def forward(self, src):
        # src shape: (batch_size, seq_len, input_dim)
        
        # 1. Project input features to embedding dim
        x = self.input_projection(src)
        
        # 2. Add positional encoding
        x = self.pos_encoder(x)
        
        # 3. Pass through Transformer Encoder
        seq_len = src.size(1)
        mask = self.generate_square_subsequent_mask(seq_len, src.device)
        out = self.transformer_encoder(x, mask=mask)
        
        # State transition predictions for all timesteps
        state_predictions = self.future_state_head(out)
        
        # 4. Extract final state representation
        final_state_repr = out[:, -1, :]
        final_state_repr = self.layer_norm(final_state_repr)
        
        # 5. Generate predictions
        now_pred = self.classification_head(final_state_repr)
        future_preds = self.forecasting_head(final_state_repr)
        
        future_preds['now'] = now_pred
        return future_preds, state_predictions
